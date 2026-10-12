# Release checklist

1. Build with GCC and Clang using `-Dwerror=true`.
2. Run `meson test --print-errorlogs` in release and ASan/UBSan builds.
3. Run both fuzz targets (`fuzz-v3-text`, `fuzz-decrypt-file`) with the
   committed seed corpus in `tests/corpus` (refresh the legacy seeds with
   `GTKCRYPTO_TEST_FIXTURE_DIR=tests/corpus build/tests/core-test`).
4. Run `ninja -C build scan-build` and confirm no findings.
5. Validate AppStream metadata and perform a DESTDIR installation.
6. Confirm v1/v2 fixture decryption and v3 deterministic structure tests.
7. Confirm failed authentication leaves existing destinations byte-identical.
8. Build `meson dist`, inspect its contents, sign the archive, then tag.
9. Publish migration notes and any coordinated security advisory.
