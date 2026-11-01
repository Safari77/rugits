use crate::parser::{
    FindPrincipalsRequest, MAX_KEY_BLOB_LEN, MAX_KEY_TEXT_LEN, SignerError, current_unix_timestamp,
    parse_allowed_signer_line, read_file_bytes, read_file_str,
};
use crate::verify::{check_key_not_revoked, validate_signer_options};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ssh_key::{PublicKey, SshSig};

const MAX_MATCHED_PRINCIPALS: usize = 64;

fn collect_principals<'a>(
    principals_field: &'a str,
    out: &mut [&'a str; MAX_MATCHED_PRINCIPALS],
    count: &mut usize,
) -> Result<(), SignerError<'static>> {
    let unquoted = principals_field.strip_prefix('"').unwrap_or(principals_field);
    let unquoted = unquoted.strip_suffix('"').unwrap_or(unquoted);

    for raw in unquoted.split(',') {
        let principal = raw.trim();
        if principal.is_empty() {
            continue;
        }
        let already_present = out.get(..*count).is_some_and(|slice| slice.contains(&principal));
        if !already_present {
            let slot = out
                .get_mut(*count)
                .ok_or(SignerError::Static("matched principals capacity exceeded"))?;
            *slot = principal;
            *count = count.saturating_add(1);
        }
    }
    Ok(())
}

pub fn execute_find_principals<'a>(req: &FindPrincipalsRequest<'a>) -> Result<(), SignerError<'a>> {
    let mut sig_buf = Vec::new();
    let sig_pem = read_file_str(req.signature_path, "signature file (-s)", &mut sig_buf)?;
    let ssh_sig = SshSig::from_pem(sig_pem.as_bytes()).map_err(|source| SignerError::SshKey {
        context: "invalid signature format in signature file (-s)",
        path: Some(req.signature_path),
        source,
    })?;

    if ssh_sig.version() != SshSig::VERSION {
        return Err(SignerError::Static("unsupported SSH signature version"));
    }

    let sig_namespace = ssh_sig.namespace();
    if let Some(expected_ns) = req.namespace
        && sig_namespace != expected_ns
    {
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

    let verify_timestamp = match req.verify_time {
        Some(ts) => ts,
        None => current_unix_timestamp()?,
    };

    let mut signers_buf = Vec::new();
    let signers_text =
        read_file_str(req.allowed_signers_path, "allowed_signers file (-f)", &mut signers_buf)?;

    let mut candidate_blob_buf = [0u8; MAX_KEY_BLOB_LEN];
    let mut matched_blob_buf = [0u8; MAX_KEY_BLOB_LEN];
    let mut matched_blob_len = 0usize;
    let mut matched_pub: Option<PublicKey> = None;

    let mut principals_list = [""; MAX_MATCHED_PRINCIPALS];
    let mut principals_count = 0usize;

    for (idx, line) in signers_text.lines().enumerate() {
        let linenum = idx.saturating_add(1);
        let Some(entry) = parse_allowed_signer_line(line)? else {
            continue;
        };

        let written = BASE64.decode_slice(entry.key_b64.as_bytes(), &mut candidate_blob_buf)?;
        let candidate_blob = candidate_blob_buf
            .get(..written)
            .ok_or(SignerError::Static("candidate key blob slice out of bounds"))?;
        let candidate_pub =
            PublicKey::from_bytes(candidate_blob).map_err(|source| SignerError::SshKey {
                context: "invalid public key in allowed_signers file (-f)",
                path: Some(req.allowed_signers_path),
                source,
            })?;

        if candidate_pub.algorithm().as_str() == entry.key_type
            && candidate_pub.key_data() == ssh_sig.public_key()
        {
            if let Some(opts) = entry.options
                && !validate_signer_options(
                    req.allowed_signers_path,
                    linenum,
                    opts,
                    req.namespace,
                    verify_timestamp,
                )?
            {
                continue;
            }
            if matched_pub.is_none() {
                let dest = matched_blob_buf
                    .get_mut(..written)
                    .ok_or(SignerError::Static("matched key blob buffer overflow"))?;
                dest.copy_from_slice(candidate_blob);
                matched_blob_len = written;
                matched_pub = Some(candidate_pub);
            }
            collect_principals(entry.principals, &mut principals_list, &mut principals_count)?;
        }
    }

    let authorized_pub = matched_pub.ok_or(SignerError::Static("No principal matched."))?;

    if let Some(rev_path) = req.revocation_path {
        let mut rev_buf = Vec::new();
        let rev_bytes = read_file_bytes(rev_path, "revocation file (-r)", &mut rev_buf)?;
        let matched_blob = matched_blob_buf
            .get(..matched_blob_len)
            .ok_or(SignerError::Static("matched key blob slice out of bounds"))?;
        check_key_not_revoked(rev_bytes, matched_blob)?;
    }

    if req.print_pubkey {
        let mut text_buf = [0u8; MAX_KEY_TEXT_LEN];
        let pub_line = authorized_pub.encode_openssh(&mut text_buf).map_err(|source| {
            SignerError::SshKey { context: "failed encoding public key", path: None, source }
        })?;
        println!("{pub_line}");
    }

    let matched_slice = principals_list
        .get(..principals_count)
        .ok_or(SignerError::Static("matched principals slice out of bounds"))?;
    for principal in matched_slice {
        println!("{principal}");
    }

    Ok(())
}
