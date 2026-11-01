use clap::Parser;
use ssh_key::HashAlg;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_KEY_BLOB_LEN: usize = 4_096;
pub const MAX_KEY_TEXT_LEN: usize = 8_192;

#[derive(Parser, Debug)]
#[command(
    name = "git-ssh-signer",
    about = "Drop-in ssh-keygen -Y sign, verify, check-novalidate, and find-principals replacement"
)]
pub struct Cli {
    /// Action requested by caller ("sign", "verify", "check-novalidate", or "find-principals")
    #[arg(short = 'Y', required = true)]
    pub action: String,

    /// Option flag(s) for signing or verification (may be specified multiple times)
    #[arg(short = 'O')]
    pub options: Vec<String>,

    /// Path to key file (for sign) or `allowed_signers` file (for verify and find-principals)
    #[arg(
        short = 'f',
        required_if_eq_any([
            ("action", "sign"),
            ("action", "verify"),
            ("action", "find-principals")
        ])
    )]
    pub key_path: Option<PathBuf>,

    /// Signature namespace (required for sign, verify, and check-novalidate; optional for find-principals)
    #[arg(
        short = 'n',
        required_if_eq_any([
            ("action", "sign"),
            ("action", "verify"),
            ("action", "check-novalidate")
        ])
    )]
    pub namespace: Option<String>,

    /// Signer identity to match in `allowed_signers` (required for verify); '*' for all
    #[arg(short = 'I', required_if_eq("action", "verify"))]
    pub signer_identity: Option<String>,

    /// Path to signature file (required for verify, check-novalidate, and find-principals)
    #[arg(
        short = 's',
        required_if_eq_any([
            ("action", "verify"),
            ("action", "check-novalidate"),
            ("action", "find-principals")
        ])
    )]
    pub signature_file: Option<PathBuf>,

    /// Optional path to key revocation file (for verify and find-principals)
    #[arg(short = 'r')]
    pub revocation_file: Option<PathBuf>,

    /// Optional flag passed by Git when signing with literal key strings
    #[arg(short = 'U')]
    pub literal_key: bool,

    /// Path(s) to target buffer file(s) to sign (required for sign)
    #[arg(required_if_eq("action", "sign"))]
    pub files: Vec<PathBuf>,
}

// ---------------------------------------------------------------------------
// Zero-Allocation Contextual Error Type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SignerError<'a> {
    FileIo { role: &'static str, path: &'a Path, source: std::io::Error },
    Io { context: &'static str, source: std::io::Error },
    SshKey { context: &'static str, path: Option<&'a Path>, source: ssh_key::Error },
    Base64Decode(base64::DecodeSliceError),
    Base64Encode(base64::EncodeSliceError),
    Persist { path: &'a Path, source: tempfile::PersistError },
    Utf8(std::str::Utf8Error),
    Static(&'static str),
}

impl fmt::Display for SignerError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileIo { role, path, source } => {
                write!(f, "{role} '{}': {source}", path.display())
            }
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::SshKey { context, path: Some(p), source } => {
                write!(f, "{context} '{}': {source}", p.display())
            }
            Self::SshKey { context, path: None, source } => write!(f, "{context}: {source}"),
            Self::Base64Decode(err) => write!(f, "Base64 decode error: {err}"),
            Self::Base64Encode(err) => write!(f, "Base64 encode error: {err}"),
            Self::Persist { path, source } => {
                write!(f, "atomic file persistence error for '{}': {source}", path.display())
            }
            Self::Utf8(err) => write!(f, "UTF-8 validation error: {err}"),
            Self::Static(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for SignerError<'_> {}

impl From<base64::DecodeSliceError> for SignerError<'_> {
    fn from(err: base64::DecodeSliceError) -> Self {
        Self::Base64Decode(err)
    }
}

impl From<base64::EncodeSliceError> for SignerError<'_> {
    fn from(err: base64::EncodeSliceError) -> Self {
        Self::Base64Encode(err)
    }
}

impl From<std::str::Utf8Error> for SignerError<'_> {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::Utf8(err)
    }
}

// ---------------------------------------------------------------------------
// File I/O Helpers with Parameter-Role Attribution
// ---------------------------------------------------------------------------

pub fn read_file_bytes<'a, 'b>(
    path: &'a Path,
    role: &'static str,
    buf: &'b mut Vec<u8>,
) -> Result<&'b [u8], SignerError<'a>> {
    buf.clear();
    let mut file = File::open(path).map_err(|source| SignerError::FileIo { role, path, source })?;
    file.read_to_end(buf).map_err(|source| SignerError::FileIo { role, path, source })?;
    Ok(buf.as_slice())
}

pub fn read_file_str<'a, 'b>(
    path: &'a Path,
    role: &'static str,
    buf: &'b mut Vec<u8>,
) -> Result<&'b str, SignerError<'a>> {
    let bytes = read_file_bytes(path, role, buf)?;
    Ok(std::str::from_utf8(bytes)?)
}

pub fn read_bounded_str<'a, 'b>(
    path: &'a Path,
    role: &'static str,
    buf: &'b mut [u8],
) -> Result<&'b str, SignerError<'a>> {
    let mut file = File::open(path).map_err(|source| SignerError::FileIo { role, path, source })?;
    let mut total = 0usize;
    loop {
        let dest =
            buf.get_mut(total..).ok_or(SignerError::Static("key file exceeds buffer capacity"))?;
        if dest.is_empty() {
            return Err(SignerError::Static("key file exceeds buffer capacity"));
        }
        let n = file.read(dest).map_err(|source| SignerError::FileIo { role, path, source })?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n);
    }
    let slice = buf.get(..total).ok_or(SignerError::Static("invalid read length"))?;
    Ok(std::str::from_utf8(slice)?)
}

// ---------------------------------------------------------------------------
// Borrowed Command Configurations
// ---------------------------------------------------------------------------

pub struct SignRequest<'a> {
    pub key_path: &'a Path,
    pub namespace: &'a str,
    pub files: &'a [PathBuf],
    pub literal_key: bool,
    pub hash_alg: HashAlg,
    pub print_pubkey: bool,
}

pub struct VerifyRequest<'a> {
    pub allowed_signers_path: &'a Path,
    pub signer_identity: &'a str,
    pub namespace: &'a str,
    pub signature_path: &'a Path,
    pub revocation_path: Option<&'a Path>,
    pub files: &'a [PathBuf],
    pub verify_time: Option<i64>,
    pub required_hash_alg: Option<HashAlg>,
    pub print_pubkey: bool,
}

pub struct CheckRequest<'a> {
    pub namespace: &'a str,
    pub signature_path: &'a Path,
    pub files: &'a [PathBuf],
    pub required_hash_alg: Option<HashAlg>,
    pub print_pubkey: bool,
}

pub struct FindPrincipalsRequest<'a> {
    pub allowed_signers_path: &'a Path,
    pub signature_path: &'a Path,
    pub revocation_path: Option<&'a Path>,
    pub namespace: Option<&'a str>,
    pub verify_time: Option<i64>,
    pub required_hash_alg: Option<HashAlg>,
    pub print_pubkey: bool,
}

pub enum Command<'a> {
    Sign(SignRequest<'a>),
    Verify(VerifyRequest<'a>),
    CheckNoValidate(CheckRequest<'a>),
    FindPrincipals(FindPrincipalsRequest<'a>),
}

impl<'a> Command<'a> {
    pub fn from_cli(cli: &'a Cli) -> Result<Self, SignerError<'a>> {
        match cli.action.as_str() {
            "sign" => Self::parse_sign(cli),
            "verify" => Self::parse_verify(cli),
            "check-novalidate" => Self::parse_check_novalidate(cli),
            "find-principals" => Self::parse_find_principals(cli),
            _ => Err(SignerError::Static(
                "unsupported -Y action (expected \"sign\", \"verify\", \"check-novalidate\", or \"find-principals\")",
            )),
        }
    }

    fn require_non_empty_namespace(cli: &'a Cli) -> Result<&'a str, SignerError<'a>> {
        let ns = cli
            .namespace
            .as_deref()
            .ok_or(SignerError::Static("signature namespace (-n) is required"))?;
        if ns.is_empty() {
            return Err(SignerError::Static("signature namespace (-n) must not be empty"));
        }
        Ok(ns)
    }

    fn parse_sign(cli: &'a Cli) -> Result<Self, SignerError<'a>> {
        let namespace = Self::require_non_empty_namespace(cli)?;
        if cli.signer_identity.is_some()
            || cli.signature_file.is_some()
            || cli.revocation_file.is_some()
        {
            return Err(SignerError::Static("options -I, -s, and -r are not valid with -Y sign"));
        }
        let key_path = cli
            .key_path
            .as_deref()
            .ok_or(SignerError::Static("key file (-f) is required for -Y sign"))?;
        if cli.files.is_empty() {
            return Err(SignerError::Static("at least one target file is required for -Y sign"));
        }

        let mut hash_alg = HashAlg::Sha512;
        let mut print_pubkey = false;
        for opt in &cli.options {
            if opt.eq_ignore_ascii_case("print-pubkey") {
                print_pubkey = true;
            } else if let Some((k, v)) = opt.split_once('=') {
                if k.eq_ignore_ascii_case("hashalg") {
                    hash_alg = parse_hash_alg(v)?;
                } else {
                    return Err(SignerError::Static("unsupported -O option for sign"));
                }
            } else {
                return Err(SignerError::Static("unsupported -O option for sign"));
            }
        }

        Ok(Self::Sign(SignRequest {
            key_path,
            namespace,
            files: &cli.files,
            literal_key: cli.literal_key,
            hash_alg,
            print_pubkey,
        }))
    }

    fn parse_verify(cli: &'a Cli) -> Result<Self, SignerError<'a>> {
        let namespace = Self::require_non_empty_namespace(cli)?;
        if cli.literal_key {
            return Err(SignerError::Static("-U is only valid with -Y sign"));
        }
        let allowed_signers_path = cli
            .key_path
            .as_deref()
            .ok_or(SignerError::Static("allowed_signers file (-f) is required for -Y verify"))?;
        let signer_identity = cli
            .signer_identity
            .as_deref()
            .ok_or(SignerError::Static("signer identity (-I) is required for -Y verify"))?;
        if signer_identity.is_empty() {
            return Err(SignerError::Static("signer identity (-I) must not be empty"));
        }
        let signature_path = cli
            .signature_file
            .as_deref()
            .ok_or(SignerError::Static("signature file (-s) is required for -Y verify"))?;

        let mut verify_time = None;
        let mut required_hash_alg = None;
        let mut print_pubkey = false;
        for opt in &cli.options {
            if opt.eq_ignore_ascii_case("print-pubkey") {
                print_pubkey = true;
            } else if let Some((k, v)) = opt.split_once('=') {
                if k.eq_ignore_ascii_case("verify-time") {
                    verify_time = Some(parse_openssh_timestamp(v)?);
                } else if k.eq_ignore_ascii_case("hashalg") {
                    required_hash_alg = Some(parse_hash_alg(v)?);
                } else {
                    return Err(SignerError::Static("unsupported -O option for verify"));
                }
            } else {
                return Err(SignerError::Static("unsupported -O option for verify"));
            }
        }

        Ok(Self::Verify(VerifyRequest {
            allowed_signers_path,
            signer_identity,
            namespace,
            signature_path,
            revocation_path: cli.revocation_file.as_deref(),
            files: &cli.files,
            verify_time,
            required_hash_alg,
            print_pubkey,
        }))
    }

    fn parse_check_novalidate(cli: &'a Cli) -> Result<Self, SignerError<'a>> {
        let namespace = Self::require_non_empty_namespace(cli)?;
        if cli.key_path.is_some()
            || cli.signer_identity.is_some()
            || cli.revocation_file.is_some()
            || cli.literal_key
        {
            return Err(SignerError::Static(
                "options -f, -I, -r, and -U are not valid with -Y check-novalidate",
            ));
        }
        let signature_path = cli.signature_file.as_deref().ok_or(SignerError::Static(
            "signature file (-s) is required for -Y check-novalidate",
        ))?;

        let mut required_hash_alg = None;
        let mut print_pubkey = false;
        for opt in &cli.options {
            if opt.eq_ignore_ascii_case("print-pubkey") {
                print_pubkey = true;
            } else if let Some((k, v)) = opt.split_once('=') {
                if k.eq_ignore_ascii_case("verify-time") {
                    let _ = parse_openssh_timestamp(v)?;
                } else if k.eq_ignore_ascii_case("hashalg") {
                    required_hash_alg = Some(parse_hash_alg(v)?);
                } else {
                    return Err(SignerError::Static("unsupported -O option for check-novalidate"));
                }
            } else {
                return Err(SignerError::Static("unsupported -O option for check-novalidate"));
            }
        }

        Ok(Self::CheckNoValidate(CheckRequest {
            namespace,
            signature_path,
            files: &cli.files,
            required_hash_alg,
            print_pubkey,
        }))
    }

    fn parse_find_principals(cli: &'a Cli) -> Result<Self, SignerError<'a>> {
        if cli.signer_identity.is_some() || cli.literal_key || !cli.files.is_empty() {
            return Err(SignerError::Static(
                "options -I, -U, and positional files are not valid with -Y find-principals",
            ));
        }
        if let Some(ref ns) = cli.namespace
            && ns.is_empty()
        {
            return Err(SignerError::Static("signature namespace (-n) must not be empty"));
        }
        let allowed_signers_path = cli.key_path.as_deref().ok_or(SignerError::Static(
            "allowed_signers file (-f) is required for -Y find-principals",
        ))?;
        let signature_path = cli
            .signature_file
            .as_deref()
            .ok_or(SignerError::Static("signature file (-s) is required for -Y find-principals"))?;

        let mut verify_time = None;
        let mut required_hash_alg = None;
        let mut print_pubkey = false;
        for opt in &cli.options {
            if opt.eq_ignore_ascii_case("print-pubkey") {
                print_pubkey = true;
            } else if let Some((k, v)) = opt.split_once('=') {
                if k.eq_ignore_ascii_case("verify-time") {
                    verify_time = Some(parse_openssh_timestamp(v)?);
                } else if k.eq_ignore_ascii_case("hashalg") {
                    required_hash_alg = Some(parse_hash_alg(v)?);
                } else {
                    return Err(SignerError::Static("unsupported -O option for find-principals"));
                }
            } else {
                return Err(SignerError::Static("unsupported -O option for find-principals"));
            }
        }

        Ok(Self::FindPrincipals(FindPrincipalsRequest {
            allowed_signers_path,
            signature_path,
            revocation_path: cli.revocation_file.as_deref(),
            namespace: cli.namespace.as_deref(),
            verify_time,
            required_hash_alg,
            print_pubkey,
        }))
    }
}

pub fn parse_hash_alg(val: &str) -> Result<HashAlg, SignerError<'static>> {
    if val.eq_ignore_ascii_case("sha256") {
        Ok(HashAlg::Sha256)
    } else if val.eq_ignore_ascii_case("sha512") {
        Ok(HashAlg::Sha512)
    } else {
        Err(SignerError::Static("unsupported hash algorithm (expected sha256 or sha512)"))
    }
}

// ---------------------------------------------------------------------------
// Zero-Copy OpenSSH Wire Reader & Writer
// ---------------------------------------------------------------------------

pub struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SliceWriter<'a> {
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn write_bytes(&mut self, data: &[u8]) -> Result<(), SignerError<'static>> {
        let end = self
            .pos
            .checked_add(data.len())
            .ok_or(SignerError::Static("wire buffer length overflow"))?;
        let dest = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(SignerError::Static("wire buffer capacity exceeded"))?;
        dest.copy_from_slice(data);
        self.pos = end;
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<(), SignerError<'static>> {
        self.write_bytes(&val.to_be_bytes())
    }

    pub fn write_wire_bytes(&mut self, data: &[u8]) -> Result<(), SignerError<'static>> {
        let len = u32::try_from(data.len())
            .map_err(|_| SignerError::Static("wire field exceeds u32::MAX"))?;
        self.write_u32(len)?;
        self.write_bytes(data)
    }

    pub fn finish(self) -> Result<&'a [u8], SignerError<'static>> {
        self.buf.get(..self.pos).ok_or(SignerError::Static("invalid slice writer cursor"))
    }
}

pub struct WireReader<'a> {
    rest: &'a [u8],
}

impl<'a> WireReader<'a> {
    pub const fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }

    pub fn read_u32(&mut self) -> Result<u32, SignerError<'static>> {
        let (head, tail) = self
            .rest
            .split_at_checked(4)
            .ok_or(SignerError::Static("unexpected EOF reading wire u32"))?;
        self.rest = tail;
        let bytes: [u8; 4] =
            head.try_into().map_err(|_| SignerError::Static("invalid 4-byte wire length"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8], SignerError<'static>> {
        let raw_len = self.read_u32()?;
        let len = usize::try_from(raw_len)
            .map_err(|_| SignerError::Static("wire field length overflow"))?;
        let (payload, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or(SignerError::Static("unexpected EOF reading wire payload"))?;
        self.rest = tail;
        Ok(payload)
    }
}

// ---------------------------------------------------------------------------
// Allowed Signers, Wildcards & Timestamps (UTC + Local TZif v1/v2/v3)
// ---------------------------------------------------------------------------

pub struct AllowedSignerEntry<'a> {
    pub principals: &'a str,
    pub options: Option<&'a str>,
    pub key_type: &'a str,
    pub key_b64: &'a str,
}

pub fn is_ssh_key_type(token: &str) -> bool {
    matches!(
        token,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ssh-dss"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
            | "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
    ) || token.starts_with("ssh-")
        || token.starts_with("ecdsa-sha2-")
        || token.starts_with("sk-ssh-")
        || token.starts_with("sk-ecdsa-")
        || token.starts_with("webauthn-sk-")
        || token.ends_with("-cert-v01@openssh.com")
}

pub fn next_token(input: &str) -> Option<(&str, &str)> {
    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let mut in_quotes = false;
    let mut split_idx = trimmed.len();
    for (idx, ch) in trimmed.char_indices() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if !in_quotes && ch.is_ascii_whitespace() {
            split_idx = idx;
            break;
        }
    }
    let (token, rest) = trimmed.split_at_checked(split_idx)?;
    if token.is_empty() { None } else { Some((token, rest)) }
}

pub fn parse_allowed_signer_line(
    line: &str,
) -> Result<Option<AllowedSignerEntry<'_>>, SignerError<'static>> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    let Some((principals, after_principals)) = next_token(trimmed) else {
        return Ok(None);
    };
    let principals =
        principals.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(principals);

    let opts_region = after_principals.trim_start();
    let (second, rest) = next_token(opts_region)
        .ok_or(SignerError::Static("malformed allowed_signers line: missing key type"))?;

    if is_ssh_key_type(second) {
        let (key_b64, _) = next_token(rest)
            .ok_or(SignerError::Static("malformed allowed_signers line: missing key data"))?;
        return Ok(Some(AllowedSignerEntry {
            principals,
            options: None,
            key_type: second,
            key_b64,
        }));
    }

    let mut cursor = rest;
    while let Some((tok, next_rest)) = next_token(cursor) {
        if is_ssh_key_type(tok) {
            let opts_len = opts_region.len().saturating_sub(cursor.len());
            let raw_opts = opts_region.get(..opts_len).map(str::trim).filter(|s| !s.is_empty());
            let (key_b64, _) = next_token(next_rest)
                .ok_or(SignerError::Static("malformed allowed_signers line: missing key data"))?;
            return Ok(Some(AllowedSignerEntry {
                principals,
                options: raw_opts,
                key_type: tok,
                key_b64,
            }));
        }
        cursor = next_rest;
    }

    Err(SignerError::Static("unrecognized SSH key type in allowed_signers"))
}

pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let mut p_idx = 0usize;
    let mut t_idx = 0usize;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    while let Some(&t_byte) = t.get(t_idx) {
        if let Some(&p_byte) = p.get(p_idx) {
            if p_byte == b'?' || p_byte == t_byte {
                p_idx += 1;
                t_idx += 1;
                continue;
            }
            if p_byte == b'*' {
                star_idx = Some(p_idx);
                match_idx = t_idx;
                p_idx += 1;
                continue;
            }
        }
        if let Some(s_idx) = star_idx {
            p_idx = s_idx + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p.get(p_idx) == Some(&b'*') {
        p_idx += 1;
    }

    p_idx == p.len()
}

pub fn match_pattern_list(pattern_list: &str, item: &str) -> bool {
    let list = pattern_list.strip_prefix('"').unwrap_or(pattern_list);
    let list = list.strip_suffix('"').unwrap_or(list);
    let mut matched = false;
    for raw_pat in list.split(',') {
        let pat = raw_pat.trim();
        if pat.is_empty() {
            continue;
        }
        if let Some(negated) = pat.strip_prefix('!') {
            if wildcard_match(negated, item) {
                return false;
            }
        } else if wildcard_match(pat, item) {
            matched = true;
        }
    }
    matched
}

pub fn split_next_option(input: &str) -> Option<(&str, &str)> {
    let trimmed = input.trim_start_matches(|c: char| c == ',' || c.is_ascii_whitespace());
    if trimmed.is_empty() {
        return None;
    }
    let mut in_quotes = false;
    let mut split_idx = trimmed.len();
    for (idx, ch) in trimmed.char_indices() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if !in_quotes && (ch == ',' || ch.is_ascii_whitespace()) {
            split_idx = idx;
            break;
        }
    }
    let (opt, rest) = trimmed.split_at_checked(split_idx)?;
    let tail = rest.trim_start_matches(|c: char| c == ',' || c.is_ascii_whitespace());
    Some((opt.trim(), tail))
}

const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

const fn max_days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Formats a Unix timestamp (`i64` seconds) into OpenSSH's `YYYYMMDDHHMMSSZ` UTC format.
pub fn format_openssh_timestamp_utc(unix_secs: i64) -> [u8; 15] {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = (if m <= 2 { y + 1 } else { y }).clamp(0, 9_999);

    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    let mut out = [b'0'; 15];
    let mut vals = [
        (0usize, 4usize, year),
        (4, 2, m),
        (6, 2, d),
        (8, 2, hour),
        (10, 2, minute),
        (12, 2, second),
    ];
    for &mut (start, width, mut v) in &mut vals {
        for idx in (start..start + width).rev() {
            if let Some(slot) = out.get_mut(idx) {
                *slot = b'0' + u8::try_from(v.rem_euclid(10)).unwrap_or(0);
            }
            v /= 10;
        }
    }
    out[14] = b'Z';
    out
}

/// Converts a civil date `(year, month, day)` into days since `1970-01-01`.
const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let m = i64::from(month);
    let d = i64::from(day);
    let y = if m <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn read_be_i32_at(buf: &[u8], offset: usize) -> Option<i32> {
    let bytes: [u8; 4] = buf.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(i32::from_be_bytes(bytes))
}

fn read_be_i64_at(buf: &[u8], offset: usize) -> Option<i64> {
    let bytes: [u8; 8] = buf.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(i64::from_be_bytes(bytes))
}

fn parse_tzif_block(block: &[u8], is_v2: bool, target_unix: i64) -> Option<i64> {
    let header = block.get(..44)?;
    if header.get(..4)? != b"TZif" {
        return None;
    }
    let tzh_ttisutcnt = usize::try_from(read_be_i32_at(header, 20)?).ok()?;
    let tzh_ttisstdcnt = usize::try_from(read_be_i32_at(header, 24)?).ok()?;
    let tzh_leapcnt = usize::try_from(read_be_i32_at(header, 28)?).ok()?;
    let tzh_timecnt = usize::try_from(read_be_i32_at(header, 32)?).ok()?;
    let tzh_typecnt = usize::try_from(read_be_i32_at(header, 36)?).ok()?;
    let tzh_charcnt = usize::try_from(read_be_i32_at(header, 40)?).ok()?;

    if tzh_typecnt == 0 {
        return None;
    }

    let time_size: usize = if is_v2 { 8 } else { 4 };
    let times_offset: usize = 44;
    let types_offset = times_offset.checked_add(tzh_timecnt.checked_mul(time_size)?)?;
    let ttinfo_offset = types_offset.checked_add(tzh_timecnt)?;

    if !is_v2 && header.get(4).copied().unwrap_or(0) >= b'2' {
        let leap_size: usize = 8;
        let v1_end = ttinfo_offset
            .checked_add(tzh_typecnt.checked_mul(6)?)?
            .checked_add(tzh_charcnt)?
            .checked_add(tzh_leapcnt.checked_mul(leap_size)?)?
            .checked_add(tzh_ttisstdcnt)?
            .checked_add(tzh_ttisutcnt)?;
        if let Some(v2_block) = block.get(v1_end..)
            && let Some(offset) = parse_tzif_block(v2_block, true, target_unix)
        {
            return Some(offset);
        }
    }

    let mut chosen_type_idx: usize = 0;
    if tzh_timecnt > 0 {
        let mut matched: Option<usize> = None;
        for i in 0..tzh_timecnt {
            let t_pos = times_offset.checked_add(i.checked_mul(time_size)?)?;
            let trans_time = if is_v2 {
                read_be_i64_at(block, t_pos)?
            } else {
                i64::from(read_be_i32_at(block, t_pos)?)
            };
            if target_unix >= trans_time {
                let type_idx = usize::from(*block.get(types_offset.checked_add(i)?)?);
                matched = Some(type_idx);
            } else {
                break;
            }
        }
        if let Some(idx) = matched {
            chosen_type_idx = idx;
        } else {
            for i in 0..tzh_typecnt {
                let info_pos = ttinfo_offset.checked_add(i.checked_mul(6)?)?;
                let is_dst = *block.get(info_pos.checked_add(4)?)?;
                if is_dst == 0 {
                    chosen_type_idx = i;
                    break;
                }
            }
        }
    }

    if chosen_type_idx >= tzh_typecnt {
        return None;
    }
    let info_pos = ttinfo_offset.checked_add(chosen_type_idx.checked_mul(6)?)?;
    let utoff = read_be_i32_at(block, info_pos)?;
    Some(i64::from(utoff))
}

fn local_utc_offset_secs(approx_unix: i64) -> i64 {
    let Ok(mut file) = File::open("/etc/localtime") else {
        return 0;
    };
    let mut buf = [0u8; 8_192];
    let mut total = 0usize;
    while let Some(dest) = buf.get_mut(total..) {
        if dest.is_empty() {
            break;
        }
        match file.read(dest) {
            Ok(0) | Err(_) => break,
            Ok(n) => total = total.saturating_add(n),
        }
    }
    let Some(slice) = buf.get(..total) else {
        return 0;
    };
    let first_pass = parse_tzif_block(slice, false, approx_unix).unwrap_or(0);
    let refined_unix = approx_unix.saturating_sub(first_pass);
    parse_tzif_block(slice, false, refined_unix).unwrap_or(first_pass)
}

/// Parses an OpenSSH timestamp (`YYYYMMDD[HHMM[SS]][Z]`) into a Unix epoch
/// timestamp (`i64` seconds). Per `ssh-keygen(1)`, timestamps ending in `Z`
/// are interpreted in UTC; timestamps without `Z` are interpreted in the
/// local system timezone.
pub fn parse_openssh_timestamp(raw: &str) -> Result<i64, SignerError<'static>> {
    let unquoted = raw.strip_prefix('"').unwrap_or(raw);
    let unquoted = unquoted.strip_suffix('"').unwrap_or(unquoted);
    let (digits, is_utc) = if let Some(stripped) = unquoted.strip_suffix(['Z', 'z']) {
        (stripped, true)
    } else {
        (unquoted, false)
    };

    let parsed: u64 =
        digits.parse().map_err(|_| SignerError::Static("invalid OpenSSH timestamp digits"))?;

    let normalized = match digits.len() {
        8 => parsed.saturating_mul(1_000_000),
        12 => parsed.saturating_mul(100),
        14 => parsed,
        _ => {
            return Err(SignerError::Static(
                "invalid OpenSSH timestamp length (expected YYYYMMDD[HHMM[SS]][Z])",
            ));
        }
    };

    let year = i64::try_from(normalized / 10_000_000_000)
        .map_err(|_| SignerError::Static("timestamp year overflow"))?;
    let month = u32::try_from((normalized / 100_000_000) % 100).unwrap_or(0);
    let day = u32::try_from((normalized / 1_000_000) % 100).unwrap_or(0);
    let hour = i64::try_from((normalized / 10_000) % 100).unwrap_or(99);
    let minute = i64::try_from((normalized / 100) % 100).unwrap_or(99);
    let second = i64::try_from(normalized % 100).unwrap_or(99);

    let max_day = max_days_in_month(year, month);
    if !(1970..=9999).contains(&year)
        || max_day == 0
        || day < 1
        || day > max_day
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(SignerError::Static("OpenSSH timestamp out of calendar range"));
    }

    let days = days_from_civil(year, month, day);
    let nominal_secs = days
        .saturating_mul(86_400)
        .saturating_add(hour.saturating_mul(3_600))
        .saturating_add(minute.saturating_mul(60))
        .saturating_add(second.min(59));

    if is_utc {
        Ok(nominal_secs)
    } else {
        let offset = local_utc_offset_secs(nominal_secs);
        Ok(nominal_secs.saturating_sub(offset))
    }
}

pub fn current_unix_timestamp() -> Result<i64, SignerError<'static>> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SignerError::Static("system clock is earlier than UNIX_EPOCH"))?
        .as_secs();
    i64::try_from(secs).map_err(|_| SignerError::Static("system clock timestamp overflow"))
}
