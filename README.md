# GTKCrypto

A GTK 4 / libadwaita application for encrypting files and text, computing hashes, and signing files with GPG. Ships with a command-line companion (`gtkcrypto-cli`) for hashing and file encryption from the terminal.

## Features

- **File Encryption/Decryption** -- AES-256, Twofish, Serpent, or Camellia in GCM (recommended), CTR, or CBC mode. Multi-file support with threaded operations.
- **Text Encryption/Decryption** -- AES-256-GCM with PBKDF2 key derivation. Output is base64-encoded.
- **File Hashing** -- MD5, SHA-1, GOST94, SHA-256, SHA3-256, BLAKE2b-256, SHA-384, SHA3-384, SHA-512, SHA3-512, BLAKE2b-512, and Whirlpool. All enabled algorithms compute in parallel as soon as a file is selected; the selection is remembered across sessions.
- **Verify against an expected hash** -- paste a known-good hash and the matching algorithm row is highlighted.
- **Hash Comparison** -- Compare two files by hash to verify integrity.
- **GPG Signing & Verification** -- Sign files with your GPG keys and verify detached signatures.
- **Drag-and-drop everywhere** -- drop files onto any file input (hashing, encrypt/decrypt, GPG sign/verify).
- **Command-line interface** -- `gtkcrypto-cli` for hashing and file encrypt/decrypt without the GUI.

## Security

### File Encryption
- **GCM mode (recommended):** authenticated encryption with built-in integrity via GCM tag. No separate HMAC needed.
- **CBC/CTR modes:** encrypt-then-MAC with HMAC-SHA3-512 computed over the full file (metadata + ciphertext).
- Confidentiality: AES/Twofish/Serpent/Camellia with 256-bit keys.
- Key derivation: PBKDF2 with 600,000 iterations using SHA-512 (OWASP 2024 recommendation).
- Passwords and keys are stored in gcrypt secure memory and cleared with `explicit_bzero`.
- Encrypted file format (v2): `magic ("GTC") | version | metadata (IV + salt + algo + mode + padding) | ciphertext | GCM tag or HMAC-SHA3-512`
- Backward compatible: files encrypted with v1 (100,000 iterations, no magic header) are still decryptable.

### Text Encryption
- AES-256-GCM (authenticated encryption).
- Key derivation: PBKDF2 with 600,000 iterations using SHA-512.
- All sensitive data stored in gcrypt secure memory.
- Output format: `base64(IV | salt | ciphertext | GCM tag)`

## Requirements

| Dependency | Minimum Version |
|------------|-----------------|
| GTK        | 4.16            |
| libadwaita | 1.6             |
| GLib       | 2.76            |
| libgcrypt  | 1.10.1          |
| gpgme      | 1.8.0           |
| Meson      | 0.62            |

## Building

```sh
git clone https://github.com/paolostivanin/GTKCrypto.git
cd GTKCrypto
meson setup builddir
ninja -C builddir
sudo ninja -C builddir install
```

## Command-line interface

Both `gtkcrypto` (GUI) and `gtkcrypto-cli` (CLI) are installed by `meson install`. The CLI does not link against GTK or libadwaita and is suitable for headless use.

```sh
# Hash (output matches sha256sum)
gtkcrypto-cli hash README.md
gtkcrypto-cli hash --algo sha256,sha512,blake2b-256 README.md

# Encrypt (prompts for password; defaults to AES-256-GCM)
gtkcrypto-cli encrypt secret.pdf
gtkcrypto-cli encrypt --cipher twofish --mode ctr secret.pdf

# Decrypt (use --delete to remove the .enc after success)
gtkcrypto-cli decrypt secret.pdf.enc

# Non-interactive: read the password from a file
gtkcrypto-cli encrypt --password-file ~/.secrets/pw secret.pdf
```

Run `gtkcrypto-cli --help` or `gtkcrypto-cli SUBCOMMAND --help` for the full reference.

Files encrypted with the GUI can be decrypted with the CLI and vice versa -- both share the same crypto core.

## Verifying the Encryption

Don't trust the program blindly -- trust the code. You can encrypt a file with GTKCrypto and write your own decryption tool. The encrypted file structure is documented in [`src/crypt-common.h`](src/crypt-common.h).

## License

GNU General Public License v3.0 or later.
