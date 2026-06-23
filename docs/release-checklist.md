# Release checklist

1. Build with GCC and Clang using `-Dwerror=true`.
2. Run `meson test --print-errorlogs` in release and ASan/UBSan builds.
3. Run the fuzz target with the committed seed corpus.
4. Validate AppStream metadata and perform a DESTDIR installation.
5. Confirm v1/v2 fixture decryption and v3 deterministic structure tests.
6. Confirm failed authentication leaves existing destinations byte-identical.
7. Build `meson dist`, inspect its contents, sign the archive, then tag.
8. Publish migration notes and any coordinated security advisory.
