# rugits

A Rust drop-in replacement for OpenSSH `ssh-keygen -Y` signature operations (`sign`, `verify`, `check-novalidate`, and `find-principals`), designed for Git commit/tag signing and general OpenSSH `SSHSIG` workflows.

`verify -I *` is supported so `git verify-commit` and `git verify-tag` need to execute `gpg.ssh.program` only once instead of twice with stock Git and OpenSSH `ssh-keygen`. The patch for Git is in `assets/git-verify-Istar.patch`.

---

## Key Features

- **Full OpenSSH `PROTOCOL.sshsig` Compatibility**: Supports `sign`, `verify`, `check-novalidate`, and `find-principals` actions compliant with the OpenSSH signature specification (Version 1).

- **Single-Pass Verification (`-Y verify -I *`)**: Resolves the signer principal directly from `allowed_signers` during `-Y verify` when `-I *` is passed, eliminating the separate `-Y find-principals` subprocess invocation required by stock Git. If a signature is cryptographically valid but its key is not present in `allowed_signers`, `verify -I *` outputs the untrusted key fingerprint summary (`Good "<namespace>" signature with <key_type> key <fingerprint>`) before exiting non-zero so Git can still report the signing key fingerprint without a fallback `check-novalidate` call.

- **Zero-Allocation Hot Path**: Engineered with stack-allocated wire buffers (`SliceWriter` and `WireReader`), in-place Base64 encoding/decoding, and explicit lifetime borrowing (`<'a>`) to avoid heap allocations, `.clone()`, or unnecessary memory copies.

- **Direct & Agent-Backed Signing**:

  * Directly signs payloads using unencrypted OpenSSH private keys (`ed25519`, `rsa`, `ecdsa`) on disk.
  * Automatically falls back to `ssh-agent` via `SSH_AUTH_SOCK` (`SSH2_AGENTC_SIGN_REQUEST`) when the key is encrypted, when only a `.pub` key is present, or when `-U` (literal public key mode) is specified. Prompts for passphrase using the `rpassword` crate if `SSH_AUTH_SOCK` is not available.
- **TOCTOU-Safe Atomic Signature Output**: Writes `.sig` files using `tempfile::NamedTempFile` in the target file's parent directory (mode `0600`), synced to disk via `fsync` and atomically persisted via POSIX `rename(2)` to prevent symlink traversal and race conditions.

- **Comprehensive `allowed_signers` Engine**:

  * Supports comma-separated principal pattern lists with `*` and `?` wildcards and `!` negation, as well as quoted principals and space- or comma-separated option blocks.
  * Recognizes standard (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-*`), security key (`sk-*`, `webauthn-sk-*`), and certificate (`*-cert-v01@openssh.com`) key type tokens.
  * Matches the signing key prior to evaluating per-key options (`namespaces=...`, `valid-after=...`, `valid-before=...`) and emits OpenSSH-compatible `<path>:<linenum>: ...` diagnostics to `stderr` when a matched key is rejected by an option constraint.
  * Queries and resolves matching principals via `-Y find-principals` while enforcing option and revocation rules.
- **Timezone-Aware Timestamp Parsing & Formatting**:

  * Parses OpenSSH timestamps in `YYYYMMDD`, `YYYYMMDDHHMM`, and `YYYYMMDDHHMMSS` formats.
  * Evaluates `Z`/`z`-suffixed timestamps in UTC and unsuffixed timestamps in the local system timezone by parsing `/etc/localtime` (`TZif` v1, v2, and v3 64-bit transition tables) in-place without `unsafe` FFI calls.
  * Formats timestamps in UTC (`YYYYMMDDHHMMSSZ`) for `valid-after` / `valid-before` diagnostic messages.
- **Key Revocation Support (`-r`)**: Supports both OpenSSH plain-text public key revocation lists and binary `SSHKRL` (`SSHKRL\n\0`) files across verification and principal lookup.

- **Parameter-Attributed Error Diagnostics**: Pinpoints the exact CLI flag (`-f`, `-s`, `-r`, or target file) alongside the file path whenever an I/O or parsing error occurs.

- **Memory-Safe & Strict Lints**: Built with `#![forbid(unsafe_code)]` and passes `clippy::pedantic`, `clippy::perf`, and `clippy::indexing_slicing` with zero warnings.


---

## Supported Operations

### 1. Sign (`-Y sign`)

Signs one or more files and writes the resulting armored OpenSSH signature to `<file>.sig` for each input file.
This deviates from OpenSSH’s `ssh-keygen -Y sign`, which has a TOCTOU bug when writing the signature file and prompts interactively before overwriting an existing `.sig` file.

```text
rugits -Y sign [-O option] [-U] -f key_file -n namespace file ...
```

- Required flags: `-f <key_file>`, `-n <namespace>`, and at least one `<file>`.

- Optional flags: `-O hashalg=sha256|sha512`, `-O print-pubkey`, `-U`.


### 2. Verify (`-Y verify`)

Verifies a signature against an `allowed_signers` file, a signer identity (`-I`, or `-I *` to auto-resolve the first matching non-negated principal from `allowed_signers`), and a signature namespace (`-n`). Reads the signed message from the first positional file argument if provided, or from standard input (`stdin`) otherwise.

This deviates from OpenSSH’s `ssh-keygen -Y verify`, which silently ignores positional file arguments and reads only from `STDIN_FILENO`, and requires an explicit principal identity instead of `-I *`.

```text
rugits -Y verify [-O option] -f allowed_signers_file -I signer_identity -n namespace -s signature_file [-r revocation_file] [file]
```

- Required flags: `-f <allowed_signers_file>`, `-I <signer_identity>` (or `-I *`), `-n <namespace>`, `-s <signature_file>`.

- Optional flags: `-r <revocation_file>`, `-O verify-time=<timestamp>`, `-O hashalg=sha256|sha512`, `-O print-pubkey`, `[file]`.


### 3. Check Without Authorization (`-Y check-novalidate`)

Checks that a signature has a valid `SSHSIG` structure, matches the requested namespace (`-n`), and cryptographically verifies against the public key embedded inside the signature itself without checking an `allowed_signers` file. Reads the message from a positional file or standard input (`stdin`).

```text
rugits -Y check-novalidate [-O option] -n namespace -s signature_file [file]
```

- Required flags: `-n <namespace>`, `-s <signature_file>`.

- Optional flags: `-O verify-time=<timestamp>`, `-O hashalg=sha256|sha512`, `-O print-pubkey`, `[file]`.


---

### 4. Find Principals (`-Y find-principals`)

Finds and prints all principals in an `allowed_signers` file that are authorized to sign using the public key embedded in a given signature file. Validates that the signature has not expired or been revoked and matches namespace and hash algorithm constraints if supplied.

```text
rugits -Y find-principals [-O option] -f allowed_signers_file -s signature_file [-n namespace] [-r revocation_file]
```

- Required flags: `-f <allowed_signers_file>`, `-s <signature_file>`.

- Optional flags: `-n <namespace>`, `-r <revocation_file>`, `-O verify-time=<timestamp>`, `-O hashalg=sha256|sha512`, `-O print-pubkey`.


---


## Command-Line Options Reference

| Option | Argument | Applicable Actions | Description |
| :--- | :--- | :--- | :--- |
| `-Y` | `sign` \| `verify` \| `check-novalidate` \| `find-principals` | All (Required) | Specifies the OpenSSH signature operation to execute. |
| `-f` | `<path>` | `sign`, `verify`, `find-principals` (Required) | Path to the private/public key file (for `sign`) or the `allowed_signers` file (for `verify` and `find-principals`). |
| `-n` | `<namespace>` | `sign`, `verify`, `check-novalidate` (Required); `find-principals` (Optional) | Signature namespace (e.g., `git` or `file`). Prevents cross-protocol signature replay. |
| `-I` | `<signer_identity>` \| `*` | `verify` (Required) | Principal identity to match in the `allowed_signers` file (e.g., `user@example.com`), or `*` to resolve the principal automatically from the matching key entry. |
| `-s` | `<signature_file>` | `verify`, `check-novalidate`, `find-principals` (Required) | Path to the `.sig` PEM signature file to verify or inspect. |
| `-r` | `<revocation_file>` | `verify`, `find-principals` (Optional) | Path to a text public-key revocation list or binary `SSHKRL` file. |
| `-U` | *(Flag)* | `sign` (Optional) | Indicates that `-f` points to a literal public key file and signing must be delegated to `ssh-agent`. |
| `-O` | `<option>` | All (Optional, Repeatable) | Passes operation-specific options (see `-O` Options table below). |
| `file ...` | `<path>...` | `sign` (Required), `verify` / `check-novalidate` (Optional) | Target file(s) to sign, or message file to verify (defaults to `stdin` for `verify` and `check-novalidate`). |

---

## Supported `-O` Options

| `-O` Value | Applicable Actions | Description |
| :--- | :--- | :--- |
| `hashalg=sha256` | `sign`, `verify`, `check-novalidate`, `find-principals` | Uses or requires `SHA-256` when hashing the signed message. |
| `hashalg=sha512` | `sign`, `verify`, `check-novalidate`, `find-principals` | Uses or requires `SHA-512` when hashing the signed message (default for `sign`). |
| `print-pubkey` | All | Prints the full OpenSSH public key line to `stdout` upon signing, successful verification, or principal resolution. |
| `verify-time=YYYYMMDD[HHMM[SS]][Z]` | `verify`, `check-novalidate`, `find-principals` | Evaluates `valid-after` and `valid-before` constraints in `allowed_signers` against the specified timestamp instead of current system time. |

---

## `allowed_signers` File Format Support

Each non-empty, non-comment (`#`) line in the `allowed_signers` file passed via `-f` during `-Y verify` or `-Y find-principals` follows the OpenSSH format:

```text
principals [options] key-type base64-encoded-key [comment]
```

### Supported `allowed_signers` Options

- `namespaces="pattern1,pattern2,..."`: Restricts the key to matching namespaces (supports `*`, `?`, and `!` negation).

- `valid-after="YYYYMMDD[HHMM[SS]][Z]"`: Rejects signatures verified before the given timestamp.

- `valid-before="YYYYMMDD[HHMM[SS]][Z]"`: Rejects signatures verified after the given timestamp.

- `cert-authority`: Recognized and skipped during standard key verification.


---

## Usage Examples

### Sign a File with an Unencrypted Private Key or `ssh-agent`

```text
rugits -Y sign -f ~/.ssh/id_ed25519 -n git payload.txt
```

Produces `payload.txt.sig` atomically.

### Verify a Signed File Against `allowed_signers`

```text
rugits -Y verify -f ~/.ssh/allowed_signers -I dev@example.com -n git -s payload.txt.sig < payload.txt
```

### Single-Pass Verify and Auto-Resolve Principal (`-I *`)

```text
rugits -Y verify -f ~/.ssh/allowed_signers -I '*' -n git -s payload.txt.sig < payload.txt
```

### Verify with a Specific Timestamp and Revocation File

```text
rugits -Y verify -O verify-time=20261030120000Z -f ~/.ssh/allowed_signers -I dev@example.com -n git -s payload.txt.sig -r ~/.ssh/revoked_keys payload.txt
```

### Validate Signature Structure Without `allowed_signers`

```text
rugits -Y check-novalidate -n git -s payload.txt.sig < payload.txt
```

### Find Authorized Principals for a Signature

```text
rugits -Y find-principals -f ~/.ssh/allowed_signers -s payload.txt.sig
```

Or scoped to a specific namespace and revocation list, also printing the signing public key:

```text
rugits -Y find-principals -O print-pubkey -f ~/.ssh/allowed_signers -n git -s payload.txt.sig -r ~/.ssh/revoked_keys
```

### Configure Git to Use `rugits`

```text
git config --global gpg.format ssh
git config --global gpg.ssh.program /path/to/rugits
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

---

## Project Structure

- `src/main.rs`: CLI entrypoint and exit-code handling.

- `src/parser.rs`: Clap CLI definitions, zero-allocation `SignerError<'a>` diagnostics, `WireReader`/`SliceWriter` primitives, `allowed_signers` tokenizer, and UTC/local `TZif` timestamp parser and UTC formatter.

- `src/sign.rs`: Direct `PrivateKey` signing, `ssh-agent` wire protocol client, and `TOCTOU`-safe `.sig` file writer.

- `src/verify.rs`: `allowed_signers` key and principal resolution (including `-I *`), option validation with `<path>:<linenum>` diagnostics, key revocation (`-r`) validation, and cryptographic verification.

- `src/check.rs`: `-Y check-novalidate` implementation for standalone signature verification against the embedded `SSHSIG` public key.

- `src/principals.rs`: `-Y find-principals` implementation for looking up matching authorized principals from `allowed_signers` by signature key and namespace.

