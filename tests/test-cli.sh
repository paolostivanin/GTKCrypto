#!/usr/bin/env bash
set -euo pipefail

cli=$1
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
