use crate::parser::{
    MAX_KEY_BLOB_LEN, MAX_KEY_TEXT_LEN, SignerError, VerifyRequest, current_unix_timestamp,
    format_openssh_timestamp_utc, is_ssh_key_type, match_pattern_list, next_token,
    parse_allowed_signer_line, parse_openssh_timestamp, read_file_bytes, read_file_str,
    split_next_option,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ssh_key::{HashAlg, PublicKey, SshSig};
use std::io::Read;
use std::path::Path;

pub(crate) fn validate_signer_options(
    path: &Path,
    linenum: usize,
    options_str: &str,
    namespace: Option<&str>,
    verify_timestamp: i64,
) -> Result<bool, SignerError<'static>> {
    let mut is_ca = false;
    let mut namespaces_pat: Option<&str> = None;
    let mut valid_after: Option<i64> = None;
    let mut valid_before: Option<i64> = None;

    let mut rest = options_str;
    while let Some((opt, tail)) = split_next_option(rest) {
        rest = tail;
        if opt.eq_ignore_ascii_case("cert-authority") {
            is_ca = true;
        } else if let Some((key, val)) = opt.split_once('=') {
            if key.eq_ignore_ascii_case("namespaces") {
                namespaces_pat = Some(val);
            } else if key.eq_ignore_ascii_case("valid-after") {
                valid_after = Some(parse_openssh_timestamp(val)?);
            } else if key.eq_ignore_ascii_case("valid-before") {
                valid_before = Some(parse_openssh_timestamp(val)?);
            } else {
                return Err(SignerError::Static("unsupported option in allowed_signers file"));
            }
        } else {
            return Err(SignerError::Static("unrecognized flag option in allowed_signers file"));
        }
    }

    if is_ca {
        return Ok(false);
    }

    if let (Some(ns_pat), Some(ns)) = (namespaces_pat, namespace)
        && !match_pattern_list(ns_pat, ns)
    {
        eprintln!(
            "{}:{linenum}: key is not permitted for use in signature namespace \"{ns}\"",
            path.display()
        );
        return Ok(false);
    }

    if let Some(after) = valid_after
        && verify_timestamp < after
    {
        let tverify_buf = format_openssh_timestamp_utc(verify_timestamp);
        let tvalid_buf = format_openssh_timestamp_utc(after);
        let tverify = std::str::from_utf8(&tverify_buf).unwrap_or("");
        let tvalid = std::str::from_utf8(&tvalid_buf).unwrap_or("");
        eprintln!(
            "{}:{linenum}: key is not yet valid: verify time {tverify} < valid-after {tvalid}",
            path.display()
        );
        return Ok(false);
    }

    if let Some(before) = valid_before
        && verify_timestamp > before
    {
        let tverify_buf = format_openssh_timestamp_utc(verify_timestamp);
        let tvalid_buf = format_openssh_timestamp_utc(before);
        let tverify = std::str::from_utf8(&tverify_buf).unwrap_or("");
        let tvalid = std::str::from_utf8(&tvalid_buf).unwrap_or("");
        eprintln!(
            "{}:{linenum}: key has expired: verify time {tverify} > valid-before {tvalid}",
            path.display()
        );
        return Ok(false);
    }

    Ok(true)
}

pub(crate) fn check_key_not_revoked(
    revocation_bytes: &[u8],
    signing_key_blob: &[u8],
) -> Result<(), SignerError<'static>> {
    if revocation_bytes.starts_with(b"SSHKRL\n\0") {
        if !signing_key_blob.is_empty()
            && revocation_bytes.windows(signing_key_blob.len()).any(|w| w == signing_key_blob)
        {
            return Err(SignerError::Static("signing key is revoked in KRL (-r)"));
        }
        return Ok(());
    }

    let text = std::str::from_utf8(revocation_bytes)?;
    let mut decode_buf = [0u8; MAX_KEY_BLOB_LEN];
    for line in text.lines() {
        let mut cursor = line;
        while let Some((tok, rest)) = next_token(cursor) {
            cursor = rest;
            if is_ssh_key_type(tok) {
                if let Some((key_b64, _)) = next_token(rest) {
                    let written = BASE64.decode_slice(key_b64.as_bytes(), &mut decode_buf)?;
                    let revoked_blob = decode_buf
                        .get(..written)
                        .ok_or(SignerError::Static("revoked key slice out of bounds"))?;
                    if revoked_blob == signing_key_blob {
                        return Err(SignerError::Static("signing key is revoked (-r)"));
                    }
                }
                break;
            }
        }
    }
    Ok(())
}

fn resolve_principal<'b>(
    principals_field: &'b str,
    requested_identity: &'b str,
) -> Option<&'b str> {
    if requested_identity == "*" {
        let unquoted = principals_field
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(principals_field);
        for raw in unquoted.split(',') {
            let p = raw.trim();
            if !p.is_empty() && !p.starts_with('!') {
                return Some(p);
            }
        }
        None
    } else if match_pattern_list(principals_field, requested_identity) {
        Some(requested_identity)
    } else {
        None
    }
}

fn find_matching_signer<'a, 'b>(
    req: &VerifyRequest<'a>,
    ssh_sig: &SshSig,
    verify_timestamp: i64,
    signers_text: &'b str,
    candidate_blob_buf: &mut [u8; MAX_KEY_BLOB_LEN],
    saw_matching_key: &mut bool,
) -> Result<Option<(PublicKey, usize, &'b str)>, SignerError<'a>>
where
    'a: 'b,
{
    for (idx, line) in signers_text.lines().enumerate() {
        let linenum = idx.saturating_add(1);
        let Some(entry) = parse_allowed_signer_line(line)? else {
            continue;
        };
        let Some(resolved_principal) = resolve_principal(entry.principals, req.signer_identity)
        else {
            continue;
        };

        let written = BASE64.decode_slice(entry.key_b64.as_bytes(), candidate_blob_buf)?;
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
            *saw_matching_key = true;
            if let Some(opts) = entry.options
                && !validate_signer_options(
                    req.allowed_signers_path,
                    linenum,
                    opts,
                    Some(req.namespace),
                    verify_timestamp,
                )?
            {
                continue;
            }
            return Ok(Some((candidate_pub, written, resolved_principal)));
        }
    }
    Ok(None)
}

pub fn execute_verify<'a>(req: &VerifyRequest<'a>) -> Result<(), SignerError<'a>> {
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

    let verify_timestamp = match req.verify_time {
        Some(ts) => ts,
        None => current_unix_timestamp()?,
    };

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

    let mut signers_buf = Vec::new();
    let signers_text =
        read_file_str(req.allowed_signers_path, "allowed_signers file (-f)", &mut signers_buf)?;

    let mut candidate_blob_buf = [0u8; MAX_KEY_BLOB_LEN];
    let mut saw_matching_key = false;
    let matched_key = find_matching_signer(
        req,
        &ssh_sig,
        verify_timestamp,
        signers_text,
        &mut candidate_blob_buf,
        &mut saw_matching_key,
    )?;

    let Some((authorized_pub, blob_len, resolved_principal)) = matched_key else {
        if !saw_matching_key && req.signer_identity == "*" {
            let embedded_pub = PublicKey::from(ssh_sig.public_key().clone());
            if embedded_pub.verify(req.namespace, msg_bytes, &ssh_sig).is_ok() {
                let fp = embedded_pub.fingerprint(HashAlg::Sha256);
                println!(
                    "Good \"{}\" signature with {} key {fp}",
                    req.namespace,
                    embedded_pub.algorithm().as_str(),
                );
            }
        }
        return Err(SignerError::Static("Could not verify signature."));
    };

    if let Some(rev_path) = req.revocation_path {
        let mut rev_buf = Vec::new();
        let rev_bytes = read_file_bytes(rev_path, "revocation file (-r)", &mut rev_buf)?;
        let matched_blob = candidate_blob_buf
            .get(..blob_len)
            .ok_or(SignerError::Static("authorized key blob out of bounds"))?;
        check_key_not_revoked(rev_bytes, matched_blob)?;
    }

    authorized_pub.verify(req.namespace, msg_bytes, &ssh_sig).map_err(|source| {
        SignerError::SshKey {
            context: "cryptographic signature verification failed for (-s)",
            path: Some(req.signature_path),
            source,
        }
    })?;

    if req.print_pubkey {
        let mut text_buf = [0u8; MAX_KEY_TEXT_LEN];
        let pub_line = authorized_pub.encode_openssh(&mut text_buf).map_err(|source| {
            SignerError::SshKey { context: "failed encoding public key", path: None, source }
        })?;
        println!("{pub_line}");
    }

    let fp = authorized_pub.fingerprint(HashAlg::Sha256);
    println!(
        "Good \"{}\" signature for {resolved_principal} with {} key {fp}",
        req.namespace,
        authorized_pub.algorithm().as_str(),
    );

    Ok(())
}
