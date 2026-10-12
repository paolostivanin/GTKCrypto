#!/usr/bin/env bash
set -euo pipefail

cli=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf 'correct horse battery staple\n' > "$tmp/password"
printf 'wrong password value\n' > "$tmp/wrong"
chmod 600 "$tmp/password" "$tmp/wrong"
printf 'CLI payload\n' > "$tmp/plain"

expected=$(sha256sum "$tmp/plain")
actual=$("$cli" hash "$tmp/plain")
test "$actual" = "$expected"

"$cli" encrypt --password-file "$tmp/password" "$tmp/plain"
test -s "$tmp/plain.enc"

set +e
"$cli" encrypt --password-file "$tmp/password" "$tmp/plain"
rc=$?
set -e
test "$rc" -eq 4

printf 'preserve destination\n' > "$tmp/recovered"
before=$(sha256sum "$tmp/recovered")
set +e
"$cli" decrypt --force --output "$tmp/recovered" \
  --password-file "$tmp/wrong" "$tmp/plain.enc"
rc=$?
set -e
test "$rc" -eq 3
test "$(sha256sum "$tmp/recovered")" = "$before"

"$cli" decrypt --force --output "$tmp/recovered" \
  --password-file "$tmp/password" "$tmp/plain.enc"
cmp "$tmp/plain" "$tmp/recovered"

# ---- hash: several algorithms and files, stdin, --check ----
printf 'second file\n' > "$tmp/plain2"
out=$("$cli" hash -a sha256,md5,sha3-256 "$tmp/plain")
test "$(printf '%s\n' "$out" | sed -n 1p)" = "$(sha256sum "$tmp/plain")"
test "$(printf '%s\n' "$out" | sed -n 2p)" = "$(md5sum "$tmp/plain")"
test "$(printf '%s\n' "$out" | wc -l)" -eq 3
test "$("$cli" hash - < "$tmp/plain")" = "$(sha256sum < "$tmp/plain")"
test "$("$cli" hash "$tmp/plain" "$tmp/plain2" | wc -l)" -eq 2

( cd "$tmp" && "$cli" hash plain plain2 > sums.txt )
( cd "$tmp" && "$cli" hash --check sums.txt > check.out )
test "$(grep -c ': OK$' "$tmp/check.out")" -eq 2
( cd "$tmp" && "$cli" hash --check --quiet sums.txt > check.out )
test ! -s "$tmp/check.out"
printf 'tampered\n' > "$tmp/plain2"
set +e
( cd "$tmp" && "$cli" hash --check sums.txt > check.out 2>/dev/null )
rc=$?
set -e
test "$rc" -eq 1
grep -q '^plain2: FAILED$' "$tmp/check.out"
printf 'second file\n' > "$tmp/plain2"

set +e
"$cli" hash -a nope "$tmp/plain" 2>/dev/null; rc=$?
set -e
test "$rc" -eq 2
set +e
"$cli" hash "$tmp/does-not-exist" 2>/dev/null; rc=$?
set -e
test "$rc" -eq 1

# ---- encrypt/decrypt: several files, delete, quiet/verbose ----
mkdir "$tmp/multi"
printf 'one\n' > "$tmp/multi/a"
printf 'two\n' > "$tmp/multi/b"
"$cli" encrypt --password-file "$tmp/password" --delete "$tmp/multi/a" "$tmp/multi/b"
test ! -e "$tmp/multi/a" && test ! -e "$tmp/multi/b"
test -s "$tmp/multi/a.enc" && test -s "$tmp/multi/b.enc"
"$cli" decrypt --password-file "$tmp/password" -v "$tmp/multi/a.enc" "$tmp/multi/b.enc" \
  2> "$tmp/verbose.err"
test "$(grep -c '^Decrypted' "$tmp/verbose.err")" -eq 2
test "$(cat "$tmp/multi/a")" = one && test "$(cat "$tmp/multi/b")" = two
"$cli" decrypt --password-file "$tmp/password" --force -q "$tmp/multi/a.enc" 2> "$tmp/quiet.err"
test ! -s "$tmp/quiet.err"

# one bad file does not stop the others, and the exit status reports it
set +e
"$cli" decrypt --password-file "$tmp/wrong" --force "$tmp/multi/a.enc" "$tmp/multi/b.enc" 2>/dev/null
rc=$?
set -e
test "$rc" -eq 3

# --output with several inputs is a usage error
set +e
"$cli" encrypt --password-file "$tmp/password" -o "$tmp/x" "$tmp/plain" "$tmp/plain2" 2>/dev/null
rc=$?
set -e
test "$rc" -eq 2

# new passwords must be long enough
printf 'short\n' > "$tmp/short"
chmod 600 "$tmp/short"
set +e
"$cli" encrypt --password-file "$tmp/short" -o "$tmp/short.enc" "$tmp/plain" 2>/dev/null
rc=$?
set -e
test "$rc" -eq 1
test ! -e "$tmp/short.enc"

# ---- password sources ----
printf 'correct horse battery staple\n' | \
  "$cli" encrypt --password-stdin -o "$tmp/stdin-pw.enc" "$tmp/plain"
"$cli" decrypt --password-fd 3 -o "$tmp/stdin-pw.out" "$tmp/stdin-pw.enc" \
  3< "$tmp/password"
cmp "$tmp/plain" "$tmp/stdin-pw.out"

# ---- pipes: stdin -> stdout, and a stronger KDF ----
"$cli" encrypt --password-file "$tmp/password" --kdf strong - < "$tmp/plain" > "$tmp/piped.enc"
test -s "$tmp/piped.enc"
"$cli" decrypt --password-file "$tmp/password" - < "$tmp/piped.enc" > "$tmp/piped.out"
cmp "$tmp/plain" "$tmp/piped.out"
"$cli" decrypt --password-file "$tmp/password" -o - "$tmp/piped.enc" | cmp - "$tmp/plain"
set +e
"$cli" encrypt --password-file "$tmp/password" --kdf bogus "$tmp/plain" 2>/dev/null
rc=$?
set -e
test "$rc" -eq 2
# no staging files may be left in the temp directory
test -z "$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name '.gtkcrypto-*' 2>/dev/null)"

# ---- interruption removes the temporary output ----
mkdir "$tmp/big"
truncate -s 3G "$tmp/big/data"
"$cli" encrypt --password-file "$tmp/password" "$tmp/big/data" &
pid=$!
sleep 0.5
kill -INT "$pid"
set +e
wait "$pid"
rc=$?
set -e
test "$rc" -eq 130
test -z "$(find "$tmp/big" -name '.data.*' -o -name 'data.enc')"
