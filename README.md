# GTKCrypto

A GTK 4 / libadwaita application for encrypting files and text, computing hashes, and signing files with GPG.

## Features

- **File Encryption/Decryption** -- AES-256, Twofish, Serpent, or Camellia in CBC or CTR mode. Multi-file support with threaded operations.
- **Text Encryption/Decryption** -- AES-256-GCM with PBKDF2 key derivation. Output is base64-encoded.
- **File Hashing** -- MD5, SHA-1, GOST94, SHA-256, SHA3-256, SHA-384, SHA3-384, SHA-512, SHA3-512, and Whirlpool.
- **Hash Comparison** -- Compare two files by hash to verify integrity.
- **GPG Signing & Verification** -- Sign files with your GPG keys and verify detached signatures.

## Security

### File Encryption
- Encrypt-then-MAC: plaintext is encrypted, then HMAC-SHA3-512 is computed over the ciphertext and appended.
- Confidentiality: AES/Twofish/Serpent/Camellia in CBC or CTR mode with 256-bit keys.
- Integrity: HMAC-SHA3-512.
- Key derivation: PBKDF2 with 100,000 iterations using SHA-512.
- Keys are stored in gcrypt secure memory, which is erased on exit.
- Encrypted file format: `metadata (IV + salt + algo + mode + padding) | ciphertext | HMAC-SHA3-512`

### Text Encryption
- AES-256-GCM (authenticated encryption).
- Key derivation: PBKDF2 with 150,000 iterations using SHA3-256.
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

## Verifying the Encryption

Don't trust the program blindly -- trust the code. You can encrypt a file with GTKCrypto and write your own decryption tool. The encrypted file structure is documented in [`src/crypt-common.h`](src/crypt-common.h).

## License

GNU General Public License v3.0 or later.
