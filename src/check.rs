use crate::parser::{
    CheckRequest, MAX_KEY_TEXT_LEN, SignerError, WireReader, read_file_bytes, read_file_str,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ssh_key::{HashAlg, PublicKey, SshSig};
use std::io::Read;

const SSHSIG_HEADER_AND_VERSION_LEN: usize = 10; // b"SSHSIG" (6 bytes) + uint32 version (4 bytes)

fn extract_embedded_public_key<'a>(
    sig_pem: &str,
    sig_path: &'a std::path::Path,
) -> Result<PublicKey, SignerError<'a>> {
    let mut b64_clean = [0u8; MAX_KEY_TEXT_LEN];
    let mut clean_len = 0usize;

    for line in sig_pem.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("-----") {
            let bytes = trimmed.as_bytes();
            let end = clean_len
                .checked_add(bytes.len())
                .ok_or(SignerError::Static("signature Base64 length overflow"))?;
            let dest = b64_clean
                .get_mut(clean_len..end)
                .ok_or(SignerError::Static("signature Base64 buffer overflow"))?;
            dest.copy_from_slice(bytes);
            clean_len = end;
        }
    }

    let b64_slice = b64_clean
        .get(..clean_len)
        .ok_or(SignerError::Static("signature Base64 slice out of bounds"))?;

    let mut raw_sig_buf = [0u8; MAX_KEY_TEXT_LEN];
    let raw_len = BASE64.decode_slice(b64_slice, &mut raw_sig_buf)?;

    let body = raw_sig_buf
        .get(SSHSIG_HEADER_AND_VERSION_LEN..raw_len)
        .ok_or(SignerError::Static("truncated SSHSIG binary envelope"))?;

    let mut reader = WireReader::new(body);
    let pub_blob = reader.read_bytes()?;

    PublicKey::from_bytes(pub_blob).map_err(|source| SignerError::SshKey {
        context: "invalid embedded public key in signature file (-s)",
        path: Some(sig_path),
        source,
    })
}

pub fn execute_check_novalidate<'a>(req: &CheckRequest<'a>) -> Result<(), SignerError<'a>> {
    let mut sig_buf = Vec::new();
    let sig_pem = read_file_str(req.signature_path, "signature file (-s)", &mut sig_buf)?;
    let ssh_sig = SshSig::from_pem(sig_pem.as_bytes()).map_err(|source| SignerError::SshKey {
        context: "invalid signature structure in signature file (-s)",
        path: Some(req.signature_path),
        source,
    })?;

    if ssh_sig.version() != SshSig::VERSION {
        return Err(SignerError::Static("unsupported SSH signature version"));
    }
    if ssh_sig.namespace() != req.namespace {
        return Err(SignerError::Static(
            "signature namespace does not match requested -n namespace",
        ));
    }
    if let Some(expected_alg) = req.required_hash_alg
        && ssh_sig.hash_alg() != expected_alg
    {
        return Err(SignerError::Static(
            "signature hash algorithm does not match requested -O hashalg",
        ));
    }

    let mut msg_buf = Vec::new();
    let msg_bytes = if let Some(first_file) = req.files.first() {
        read_file_bytes(first_file.as_path(), "input message file", &mut msg_buf)?
    } else {
        std::io::stdin().read_to_end(&mut msg_buf).map_err(|source| SignerError::Io {
            context: "failed reading message from standard input",
            source,
        })?;
        msg_buf.as_slice()
    };

    let embedded_pub = extract_embedded_public_key(sig_pem, req.signature_path)?;
    embedded_pub.verify(req.namespace, msg_bytes, &ssh_sig).map_err(|source| {
        SignerError::SshKey {
            context: "signature check failed against embedded key in (-s)",
            path: Some(req.signature_path),
            source,
        }
    })?;

    if req.print_pubkey {
        let mut text_buf = [0u8; MAX_KEY_TEXT_LEN];
        let pub_line =
            embedded_pub.encode_openssh(&mut text_buf).map_err(|source| SignerError::SshKey {
                context: "failed encoding embedded public key",
                path: None,
                source,
            })?;
        println!("{pub_line}");
    }

    let fp = embedded_pub.fingerprint(HashAlg::Sha256);
    println!(
        "Good \"{}\" signature with {} key {fp}",
        req.namespace,
        embedded_pub.algorithm().as_str(),
    );

    Ok(())
}
