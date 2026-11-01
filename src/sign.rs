use crate::parser::{
    MAX_KEY_BLOB_LEN, MAX_KEY_TEXT_LEN, SignRequest, SignerError, SliceWriter, WireReader,
    read_bounded_str, read_file_bytes,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256, Sha512};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

const MAX_PACKET_LEN: usize = 16_384;
const MAX_ENVELOPE_LEN: usize = 8_192;
const MAX_PEM_LEN: usize = 16_384;

// ---------------------------------------------------------------------------
// TOCTOU-Safe File Writing via tempfile
// ---------------------------------------------------------------------------

/// Writes the signature safely avoiding `TOCTOU` and symlink attacks:
/// 1. Allocates a secure temporary file in the target buffer's parent directory
///    with restricted POSIX permissions (0600).
/// 2. Atomically replaces `<target_file>.sig` using `NamedTempFile::persist`,
///    which executes `rename(2)`. Any existing symlink at the destination
///    is replaced rather than traversed.
fn write_sig_file_safely<'a>(target_file: &'a Path, content: &[u8]) -> Result<(), SignerError<'a>> {
    let parent = target_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut sig_os = OsString::with_capacity(target_file.as_os_str().len().saturating_add(4));
    sig_os.push(target_file.as_os_str());
    sig_os.push(".sig");
    let sig_output_path = Path::new(&sig_os);

    let mut tmp = NamedTempFile::new_in(parent).map_err(|source| SignerError::FileIo {
        role: "temporary signature file in directory",
        path: parent,
        source,
    })?;
    tmp.write_all(content).map_err(|source| SignerError::FileIo {
        role: "temporary signature file for",
        path: target_file,
        source,
    })?;
    tmp.as_file().sync_all().map_err(|source| SignerError::FileIo {
        role: "temporary signature file for",
        path: target_file,
        source,
    })?;
    tmp.persist(sig_output_path)
        .map_err(|source| SignerError::Persist { path: target_file, source })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// OpenSSH Wire Helpers & ssh-agent Client
// ---------------------------------------------------------------------------

/// Sanitizes an `OsStr` to contain only printable US-ASCII (`0x20..=0x7E`),
/// escaping control codes, quotes, backslashes, and non-ASCII bytes.
fn sanitize_os_str(s: &OsStr) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7E => out.push(char::from(b)),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out
}

/// Attempts to connect to `SSH_AUTH_SOCK`.
/// - Returns `Ok(None)` if `SSH_AUTH_SOCK` is unset or empty.
/// - If set, attempts to connect. On failure, prints a sanitized diagnostic to `stderr`
///   and returns `Err(source)`.
fn connect_ssh_agent() -> Result<Option<UnixStream>, std::io::Error> {
    let Some(sock_path) = std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()) else {
        return Ok(None);
    };

    match UnixStream::connect(&sock_path) {
        Ok(stream) => Ok(Some(stream)),
        Err(err) => {
            let safe_sock = sanitize_os_str(&sock_path);
            eprintln!("failed connecting to SSH_AUTH_SOCK \"{safe_sock}\": {err}");
            Err(err)
        }
    }
}

fn send_agent_packet(
    stream: &mut UnixStream,
    msg_type: u8,
    payload: &[u8],
) -> Result<(), SignerError<'static>> {
    let total_len = payload
        .len()
        .checked_add(1)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(SignerError::Static("agent packet payload too large"))?;
    stream.write_all(&total_len.to_be_bytes()).map_err(|source| SignerError::Io {
        context: "failed writing packet length to ssh-agent",
        source,
    })?;
    stream.write_all(&[msg_type]).map_err(|source| SignerError::Io {
        context: "failed writing message type to ssh-agent",
        source,
    })?;
    stream.write_all(payload).map_err(|source| SignerError::Io {
        context: "failed writing payload to ssh-agent",
        source,
    })?;
    stream.flush().map_err(|source| SignerError::Io {
        context: "failed flushing ssh-agent stream",
        source,
    })?;
    Ok(())
}

fn read_agent_packet<'a>(
    stream: &mut UnixStream,
    buf: &'a mut [u8],
) -> Result<(u8, &'a [u8]), SignerError<'static>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|source| SignerError::Io {
        context: "failed reading packet length from ssh-agent",
        source,
    })?;
    let len = usize::try_from(u32::from_be_bytes(len_buf))
        .map_err(|_| SignerError::Static("agent packet length overflow"))?;

    let frame =
        buf.get_mut(..len).ok_or(SignerError::Static("agent packet exceeds buffer capacity"))?;
    stream.read_exact(frame).map_err(|source| SignerError::Io {
        context: "failed reading packet payload from ssh-agent",
        source,
    })?;

    let (&msg_type, payload) =
        frame.split_first().ok_or(SignerError::Static("empty agent packet"))?;
    Ok((msg_type, payload))
}

fn find_matching_identity<'a>(
    ident_payload: &'a [u8],
    public_key_blob: &[u8],
) -> Result<Option<&'a [u8]>, SignerError<'static>> {
    let mut reader = WireReader::new(ident_payload);
    let count = reader.read_u32()?;
    for _ in 0..count {
        let key_blob = reader.read_bytes()?;
        let _comment = reader.read_bytes()?;
        if key_blob == public_key_blob {
            return Ok(Some(key_blob));
        }
    }
    Ok(None)
}

fn extract_wire_key_type(public_key_blob: &[u8]) -> Result<&[u8], SignerError<'static>> {
    let mut reader = WireReader::new(public_key_blob);
    reader.read_bytes()
}

/// Signs data using `ssh-agent` (`SSH2_AGENTC_SIGN_REQUEST`), writing the PEM
/// output directly into `pem_out` and returning a borrowed slice.
fn sign_via_ssh_agent<'a>(
    public_key_blob: &[u8],
    namespace: &str,
    hash_alg: HashAlg,
    data_to_sign: &[u8],
    pem_out: &'a mut [u8],
) -> Result<&'a [u8], SignerError<'static>> {
    let mut stream = connect_ssh_agent()
        .map_err(|source| SignerError::Io {
            context: "failed connecting to SSH_AUTH_SOCK",
            source,
        })?
        .ok_or(SignerError::Static(
            "SSH_AUTH_SOCK not set. Start ssh-agent and load your key via ssh-add.",
        ))?;
    let mut packet_buf = [0u8; MAX_PACKET_LEN];

    // 1. Verify the key is loaded in the agent
    send_agent_packet(&mut stream, SSH2_AGENTC_REQUEST_IDENTITIES, &[])?;
    let (resp_type, ident_payload) = read_agent_packet(&mut stream, &mut packet_buf)?;
    if resp_type != SSH2_AGENT_IDENTITIES_ANSWER {
        return Err(SignerError::Static(
            "Unexpected response from ssh-agent when querying identities",
        ));
    }

    if find_matching_identity(ident_payload, public_key_blob)?.is_none() {
        return Err(SignerError::Static(
            "Signing key not found in ssh-agent. Please run 'ssh-add <key>'.",
        ));
    }

    // 2. Build OpenSSH PROTOCOL.sshsig preamble buffer
    let mut preamble_buf = [0u8; 512];
    let mut preamble_writer = SliceWriter::new(&mut preamble_buf);
    preamble_writer.write_bytes(b"SSHSIG")?;
    preamble_writer.write_wire_bytes(namespace.as_bytes())?;
    preamble_writer.write_wire_bytes(b"")?; // reserved field

    let hash_name = match hash_alg {
        HashAlg::Sha256 => {
            preamble_writer.write_wire_bytes(b"sha256")?;
            let digest = Sha256::digest(data_to_sign);
            preamble_writer.write_wire_bytes(&digest)?;
            b"sha256".as_slice()
        }
        HashAlg::Sha512 => {
            preamble_writer.write_wire_bytes(b"sha512")?;
            let digest = Sha512::digest(data_to_sign);
            preamble_writer.write_wire_bytes(&digest)?;
            b"sha512".as_slice()
        }
        _ => return Err(SignerError::Static("unsupported SSHSIG hash algorithm")),
    };
    let preamble = preamble_writer.finish()?;

    // 3. Flags: 0 for Ed25519/ECDSA; 2 or 4 (RSA SHA2-256 / SHA2-512) for RSA
    let flags = if extract_wire_key_type(public_key_blob)? == b"ssh-rsa" {
        match hash_alg {
            HashAlg::Sha256 => SSH_AGENT_RSA_SHA2_256,
            _ => SSH_AGENT_RSA_SHA2_512,
        }
    } else {
        0
    };

    // 4. Request signature from ssh-agent
    let mut sign_req_buf = [0u8; MAX_ENVELOPE_LEN];
    let mut req_writer = SliceWriter::new(&mut sign_req_buf);
    req_writer.write_wire_bytes(public_key_blob)?;
    req_writer.write_wire_bytes(preamble)?;
    req_writer.write_u32(flags)?;
    let sign_req = req_writer.finish()?;

    send_agent_packet(&mut stream, SSH2_AGENTC_SIGN_REQUEST, sign_req)?;
    let (sign_resp_type, sign_payload) = read_agent_packet(&mut stream, &mut packet_buf)?;
    if sign_resp_type != SSH2_AGENT_SIGN_RESPONSE {
        return Err(SignerError::Static("ssh-agent failed to sign the requested payload"));
    }

    // Extract raw signature blob (format + signature components)
    let mut sig_reader = WireReader::new(sign_payload);
    let sig_blob = sig_reader.read_bytes()?;

    // 5. Wrap inside OpenSSH SshSig envelope
    let mut envelope_buf = [0u8; MAX_ENVELOPE_LEN];
    let mut env_writer = SliceWriter::new(&mut envelope_buf);
    env_writer.write_bytes(b"SSHSIG")?;
    env_writer.write_u32(1)?; // Version 1
    env_writer.write_wire_bytes(public_key_blob)?;
    env_writer.write_wire_bytes(namespace.as_bytes())?;
    env_writer.write_wire_bytes(b"")?; // reserved
    env_writer.write_wire_bytes(hash_name)?;
    env_writer.write_wire_bytes(sig_blob)?;
    let envelope = env_writer.finish()?;

    // Format PEM envelope with 70-character line wrapping
    let mut b64_buf = [0u8; MAX_PEM_LEN];
    let b64_len = BASE64.encode_slice(envelope, &mut b64_buf)?;
    let b64_bytes =
        b64_buf.get(..b64_len).ok_or(SignerError::Static("Base64 output slice out of bounds"))?;

    let mut pem_writer = SliceWriter::new(pem_out);
    pem_writer.write_bytes(b"-----BEGIN SSH SIGNATURE-----\n")?;
    for chunk in b64_bytes.chunks(70) {
        pem_writer.write_bytes(chunk)?;
        pem_writer.write_bytes(b"\n")?;
    }
    pem_writer.write_bytes(b"-----END SSH SIGNATURE-----\n")?;
    pem_writer.finish()
}

// ---------------------------------------------------------------------------
// Key Resolver & Sign Execution
// ---------------------------------------------------------------------------

enum PathRef<'a> {
    Borrowed(&'a Path),
    Owned(PathBuf),
}

impl PathRef<'_> {
    fn as_path(&self) -> &Path {
        match self {
            Self::Borrowed(p) => p,
            Self::Owned(p) => p.as_path(),
        }
    }
}

fn has_pub_extension(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("pub"))
}

fn resolve_priv_key_path(path: &Path) -> PathRef<'_> {
    if has_pub_extension(path) {
        PathRef::Owned(path.with_extension(""))
    } else {
        PathRef::Borrowed(path)
    }
}

fn resolve_pub_key_path(path: &Path) -> PathRef<'_> {
    if has_pub_extension(path) {
        PathRef::Borrowed(path)
    } else {
        let mut os = OsString::with_capacity(path.as_os_str().len().saturating_add(4));
        os.push(path.as_os_str());
        os.push(".pub");
        PathRef::Owned(PathBuf::from(os))
    }
}

fn decode_pubkey_text<'a>(
    openssh_pub: &str,
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], SignerError<'static>> {
    let b64 = openssh_pub
        .split_whitespace()
        .nth(1)
        .ok_or(SignerError::Static("Invalid public key format"))?;
    let written = BASE64.decode_slice(b64.as_bytes(), out_buf)?;
    out_buf.get(..written).ok_or(SignerError::Static("decoded key slice out of bounds"))
}

fn extract_public_key_blob<'a, 'b>(
    path: &'a Path,
    text_buf: &mut [u8],
    out_buf: &'b mut [u8],
) -> Result<&'b [u8], SignerError<'a>> {
    let pub_path = resolve_pub_key_path(path);
    if pub_path.as_path().exists() {
        let content = read_bounded_str(pub_path.as_path(), "public key file (-f)", text_buf)
            .map_err(|_| SignerError::SshKey {
                context: "failed reading public key file (-f)",
                path: Some(path),
                source: ssh_key::Error::FormatEncoding,
            })?;
        return decode_pubkey_text(content, out_buf);
    }

    // Support literal public key files passed without a .pub extension (e.g. via -U)
    if let Ok(content) = read_bounded_str(path, "key file (-f)", text_buf) {
        let trimmed = content.trim_start();
        if !trimmed.starts_with("-----BEGIN")
            && let Ok(blob) = decode_pubkey_text(trimmed, out_buf)
        {
            return Ok(blob);
        }
    }

    // Fall back to reading public key embedded in private key file
    let priv_key = PrivateKey::read_openssh_file(path).map_err(|source| SignerError::SshKey {
        context: "failed reading key file (-f)",
        path: Some(path),
        source,
    })?;
    let pub_str =
        priv_key.public_key().encode_openssh(text_buf).map_err(|source| SignerError::SshKey {
            context: "failed encoding public key from (-f)",
            path: Some(path),
            source,
        })?;
    decode_pubkey_text(pub_str, out_buf)
}

/// Prompts the user on the TTY for a passphrase and decrypts the given `PrivateKey`.
fn prompt_and_decrypt<'a>(
    priv_key: &PrivateKey,
    display_path: &Path,
    err_path: &'a Path,
) -> Result<PrivateKey, SignerError<'a>> {
    let prompt = format!("Enter passphrase for {}: ", display_path.display());
    let passphrase = Zeroizing::new(rpassword::prompt_password(prompt).map_err(|source| {
        SignerError::Io { context: "failed reading passphrase from terminal", source }
    })?);

    priv_key.decrypt(passphrase.as_bytes()).map_err(|source| SignerError::SshKey {
        context: "failed decrypting private key (-f)",
        path: Some(err_path),
        source,
    })
}

/// Loads the private key directly if available.
/// - Unencrypted private keys are returned immediately.
/// - Encrypted private keys check if `SSH_AUTH_SOCK` is connectable; if not (unset or
///   connection failed), prompts on the TTY for a passphrase to decrypt the key.
fn load_direct_private_key<'a>(
    req: &SignRequest<'a>,
    priv_key_path: &Path,
) -> Result<Option<PrivateKey>, SignerError<'a>> {
    if req.literal_key || !priv_key_path.exists() {
        return Ok(None);
    }

    let Ok(priv_key) = PrivateKey::read_openssh_file(priv_key_path) else {
        return Ok(None);
    };

    if !priv_key.is_encrypted() {
        return Ok(Some(priv_key));
    }

    // If SSH_AUTH_SOCK is set and connectable, let ssh-agent handle signing
    if matches!(connect_ssh_agent(), Ok(Some(_))) {
        return Ok(None);
    }

    // SSH_AUTH_SOCK is unset or failed to connect; prompt for passphrase
    let decrypted = prompt_and_decrypt(&priv_key, priv_key_path, req.key_path)?;
    Ok(Some(decrypted))
}

fn sign_payload<'a, 'b>(
    req: &SignRequest<'a>,
    priv_key_opt: Option<&PrivateKey>,
    pub_blob_opt: Option<&[u8]>,
    data_to_sign: &[u8],
    pem_out: &'b mut [u8],
) -> Result<&'b [u8], SignerError<'a>> {
    if let Some(priv_key) = priv_key_opt {
        // Direct signature using unencrypted / decrypted private key
        let sig = SshSig::sign(priv_key, req.namespace, req.hash_alg, data_to_sign).map_err(
            |source| SignerError::SshKey {
                context: "direct signing failed with key (-f)",
                path: Some(req.key_path),
                source,
            },
        )?;
        let pem = sig.to_pem(LineEnding::LF).map_err(|source| SignerError::SshKey {
            context: "PEM encoding failed",
            path: None,
            source,
        })?;
        let mut writer = SliceWriter::new(pem_out);
        writer.write_bytes(pem.as_bytes())?;
        return writer.finish();
    }

    if let Some(blob) = pub_blob_opt {
        return sign_via_ssh_agent(blob, req.namespace, req.hash_alg, data_to_sign, pem_out);
    }

    Err(SignerError::Static("no signing key resolved"))
}

pub fn execute_sign<'a>(req: &SignRequest<'a>) -> Result<(), SignerError<'a>> {
    let priv_key_path = resolve_priv_key_path(req.key_path);
    let mut text_buf = [0u8; MAX_KEY_TEXT_LEN];
    let mut key_blob_buf = [0u8; MAX_KEY_BLOB_LEN];

    // Load private key directly (or prompt for passphrase if encrypted and agent is unavailable)
    let direct_priv_key = load_direct_private_key(req, priv_key_path.as_path())?;

    // Key is encrypted (with reachable ssh-agent), literal (-U), or only public key exists -> ssh-agent
    let pub_key_blob = if let Some(ref priv_key) = direct_priv_key {
        if req.print_pubkey {
            let pub_line =
                priv_key.public_key().encode_openssh(&mut text_buf).map_err(|source| {
                    SignerError::SshKey {
                        context: "failed encoding public key",
                        path: Some(req.key_path),
                        source,
                    }
                })?;
            println!("{pub_line}");
        }
        None
    } else {
        let blob = extract_public_key_blob(req.key_path, &mut text_buf, &mut key_blob_buf)?;
        if req.print_pubkey {
            let pub_key = PublicKey::from_bytes(blob).map_err(|source| SignerError::SshKey {
                context: "invalid public key blob in (-f)",
                path: Some(req.key_path),
                source,
            })?;
            let pub_line =
                pub_key.encode_openssh(&mut text_buf).map_err(|source| SignerError::SshKey {
                    context: "failed encoding public key",
                    path: Some(req.key_path),
                    source,
                })?;
            println!("{pub_line}");
        }
        Some(blob)
    };

    let mut data_buf = Vec::new();
    let mut pem_buf = [0u8; MAX_PEM_LEN];

    if req.files.is_empty() {
        std::io::stdin().read_to_end(&mut data_buf).map_err(|source| SignerError::Io {
            context: "failed reading payload from stdin",
            source,
        })?;
        let pem_bytes =
            sign_payload(req, direct_priv_key.as_ref(), pub_key_blob, &data_buf, &mut pem_buf)?;
        std::io::stdout().write_all(pem_bytes).map_err(|source| SignerError::Io {
            context: "failed writing signature to stdout",
            source,
        })?;
        return Ok(());
    }

    for target_file in req.files {
        let target_path = target_file.as_path();
        let safe_target = sanitize_os_str(target_path.as_os_str());
        eprintln!("Signing file {safe_target}");

        let data_to_sign = read_file_bytes(target_path, "target file", &mut data_buf)?;
        let pem_bytes =
            sign_payload(req, direct_priv_key.as_ref(), pub_key_blob, data_to_sign, &mut pem_buf)?;
        write_sig_file_safely(target_path, pem_bytes)?;

        eprintln!("Write signature to {safe_target}.sig");
    }

    Ok(())
}
