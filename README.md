# GTKCrypto

GTKCrypto is a GTK 4/libadwaita application for authenticated file and text
encryption, file hashing, and detached OpenPGP signatures. A headless
`gtkcrypto-cli` companion is installed with the GUI.

## Encryption

New files use the portable GTC3 format:

- AES-256-GCM authenticated encryption
- Argon2id password derivation (19 MiB, two passes, one lane)
- random 32-byte salt and 12-byte nonce
- authenticated, fixed-width, network-byte-order metadata
- transactional mode-0600 output files

GTKCrypto can decrypt historical v1 and v2 files. New v1/v2 files cannot be
created. The byte-level format is documented in
[`docs/file-format.md`](docs/file-format.md).

Existing destinations are never replaced implicitly:

- the CLI requires `--force`;
- the GUI asks before replacing a batch;
- replacement occurs only after authentication, flushing, and closing succeed.

GTKCrypto does not provide secure deletion. Filesystems, snapshots, SSD wear
levelling, backups, and journaling make portable secure erasure unreliable.

Passwords are copied to libgcrypt secure memory for cryptographic work and
cleared afterwards. They necessarily exist briefly in GTK widgets or terminal
input buffers; copied plaintext also remains under the desktop clipboard’s
control.

## Other features

- Text encryption using `GTC3:` followed by a base64 GTC3 container
- Legacy unprefixed encrypted-text decryption
- MD5, SHA-1, GOST94, SHA-2, SHA-3, BLAKE2b, and Whirlpool hashing
- Expected-hash verification and two-file comparison
- Detached OpenPGP signing and verification through GPGME
- Parallel background operations and drag-and-drop

MD5, SHA-1, and GOST94 are provided for compatibility, not for new security
decisions.

## Requirements

| Dependency | Minimum |
|---|---:|
| GTK | 4.16 |
| libadwaita | 1.6 |
| GLib | 2.76 |
| libgcrypt | 1.10.1 |
| GPGME | 1.8 |
| Meson | 0.62 |

## Build and test

```sh
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
sudo meson install -C build
```

For a sanitizer build:

```sh
meson setup build-sanitize -Db_sanitize=address,undefined -Db_lundef=false
meson compile -C build-sanitize
meson test -C build-sanitize --print-errorlogs
```

## CLI

```sh
gtkcrypto-cli hash --algo sha256,sha512 FILE
gtkcrypto-cli encrypt FILE
gtkcrypto-cli encrypt --output ARCHIVE.enc --force FILE
gtkcrypto-cli decrypt FILE.enc
gtkcrypto-cli decrypt --output FILE --force --delete FILE.enc
```

Passwords are prompted for by default. `--password-file PATH` reads the first
line for non-interactive use; protect that file with appropriate permissions.
Run `gtkcrypto-cli SUBCOMMAND --help` for complete options.

## Security

Do not use a release solely because it compiles. Releases require passing the
Meson regression suite, GCC and Clang builds, ASan/UBSan, AppStream validation,
installation smoke tests, and the parser fuzz smoke job.

Report vulnerabilities according to [`SECURITY.md`](SECURITY.md).

## License

GNU General Public License v3.0 or later.
