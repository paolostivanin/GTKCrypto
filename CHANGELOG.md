# Changelog

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
