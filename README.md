# GTKCrypto

GTKCrypto is a GTK 4/libadwaita application for authenticated file and text
encryption, file hashing, and detached OpenPGP signatures. A headless
`gtkcrypto-cli` companion is installed with the GUI.

## Encryption

New files use the portable GTC3 format:

- AES-256-GCM authenticated encryption
- Argon2id password derivation (19 MiB, two passes, one lane by default;
  *Strong* and *Maximum* levels are available in Preferences and via
  `gtkcrypto-cli encrypt --kdf`)
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
input buffers. Decrypted text copied from the Text Encryption page is removed
from the clipboard again after a configurable delay (30 s by default), but
other applications may have read it by then.

While a file is decrypted, the plaintext is written to a private temporary file
before the authentication tag can be checked; that file is unlinked (not wiped)
when authentication fails or the operation is cancelled.

## Other features

- Text encryption using `GTC3:` followed by a base64 GTC3 container
- Legacy unprefixed encrypted-text decryption
- MD5, SHA-1, GOST94, SHA-2, SHA-3, BLAKE2b, and Whirlpool hashing
- Expected-hash verification and two-file comparison
- Detached OpenPGP signing and verification through GPGME
- Batch file encryption/decryption with progress, cancellation, a per-file
  error report, an output-folder option and drag-and-drop
- Password strength meter and random password generator
- Preferences (key derivation strength, clipboard timeout) and keyboard
  shortcuts (`Ctrl+1`–`4` switch pages, `Ctrl+,` preferences, `Ctrl+?`
  shortcut list, `Ctrl+Q` quit)
- Translatable interface (gettext); see `po/`

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
gtkcrypto-cli hash --algo sha256,sha512 FILE...
gtkcrypto-cli hash FILE... > SHA256SUMS && gtkcrypto-cli hash --check SHA256SUMS
gtkcrypto-cli encrypt FILE...
gtkcrypto-cli encrypt --kdf strong --output ARCHIVE.enc --force FILE
gtkcrypto-cli decrypt FILE.enc...
gtkcrypto-cli decrypt --output FILE --force --delete FILE.enc
tar c dir | gtkcrypto-cli encrypt --password-file pw - > dir.tar.enc
gtkcrypto-cli decrypt --password-file pw - < dir.tar.enc | tar x
```

Passwords are prompted for on the terminal by default. For non-interactive use
pass `--password-file PATH` (protect it with appropriate permissions),
`--password-fd N` or `--password-stdin`. `-q`/`-v` select quiet or verbose
output, with a progress indicator on terminals. Ctrl-C cancels cleanly and
leaves no temporary files. Run `gtkcrypto-cli SUBCOMMAND --help` or read
`man gtkcrypto-cli` for complete options.

## Security

Do not use a release solely because it compiles. Releases require passing the
Meson regression suite, GCC and Clang builds, ASan/UBSan, AppStream validation,
installation smoke tests, and the parser fuzz smoke job.

Report vulnerabilities according to [`SECURITY.md`](SECURITY.md).

## License

GNU General Public License v3.0 or later.
