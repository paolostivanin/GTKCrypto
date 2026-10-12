# Changelog

## 3.1.0 - 2026-10-12

### Fixed

- GUI: use-after-free when batch-decrypting files, and a race that could
  report a job as finished (and block the UI) while files were still queued.
- Text page: legacy decryption could read past its buffer; unchecked secure
  memory allocations in the GUI; non-local files crashed the file pickers.
- GPG: missing NULL check and leaks when signing, verification now fails if
  any signature is bad, keylist errors are reported.
- Atomic output: works on filesystems without `RENAME_NOREPLACE`, and long
  file names no longer break temporary-file creation. Inputs above the
  AES-GCM size limit are rejected up front.

### Added

- Real cancellation: Cancel button and cleanup on window close in the GUI,
  clean SIGINT/SIGTERM handling in the CLI (exit status 130).
- GUI: progress bars, file list with removal, append-on-drop, output folder,
  delete-original option, per-file error report, password strength meter and
  generator, Preferences (key derivation strength, clipboard timeout),
  keyboard shortcuts, accessibility labels and gettext infrastructure.
- Selectable Argon2id cost (standard, strong, maximum).
- CLI: several files per call, stdin/stdout piping, `--password-fd`,
  `--password-stdin`, `hash --check`, `--quiet`/`--verbose`, `--kdf`, and a
  terminal prompt that no longer relies on `getpass(3)`.
- Single-pass multi-algorithm hashing in the GUI and CLI.

### Changed

- The GTC3 header is encoded and decoded in one place (`GtkcryptoV3Header`),
  with a known-answer layout test; dead code and GUI compatibility wrappers
  were removed.
- Fuzzing covers the file decryptor (all formats) and ships a seed corpus;
  CI adds scan-build and a GUI start-up smoke test.
- Decryption accepts passwords shorter than 8 characters (only new passwords
  are checked), so legacy files stay readable.
- Decrypted text copied to the clipboard is cleared after a delay.
- Text encryption accepts up to 1 MiB and tolerates wrapped base64.

## 3.0.0 - 2026-06-23

- Added portable GTC3 AES-256-GCM/Argon2id file and text containers.
- Made encryption, decryption, and signature output transactional.
- Added explicit overwrite policy to the CLI and GUI.
- Restored bounded v1/v2 decryption and corrected Unicode password handling.
- Fixed empty/exact-buffer hashing and removed large mmap usage.
- Fixed GPG key ownership, complete signature writes, and binary file handling.
- Fixed background-task ownership and stale hash results.
- Added regression tests, sanitizer builds, AppStream validation, and fuzzing.
- Migrated the application ID to `com.github.paolostivanin.gtkcrypto`.

## 2.2.0 - 2026-05-06

- Added `gtkcrypto-cli`.
