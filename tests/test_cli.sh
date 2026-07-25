#!/usr/bin/env bash

set -euo pipefail

binary=${1:-./i2pbox}
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/i2pbox-tests.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

expect_failure() {
    local description=$1
    shift
    if "$@" >"$tmpdir/stdout" 2>"$tmpdir/stderr"; then
        fail "$description succeeded"
    fi
}

version=$($binary --version)
case "$version" in
    *"i2pbox"*"i2pd"*) ;;
    *) fail "--version did not identify i2pbox and i2pd" ;;
esac

keyfile="$tmpdir/identity.dat"
"$binary" keygen "$keyfile" 7 >"$tmpdir/keygen.out"
test -s "$keyfile" || fail "keygen did not create a key file"
test "$(stat -c '%a' "$keyfile")" = "600" || fail "keygen did not create a 0600 key file"

offlinefile="$tmpdir/offline.dat"
"$binary" offlinekeys "$offlinefile" "$keyfile" 7 1 >"$tmpdir/offlinekeys.out"
test -s "$offlinefile" || fail "offlinekeys did not create a key file"
test "$(stat -c '%a' "$offlinefile")" = "600" || fail "offlinekeys did not create a 0600 key file"

expect_failure "keygen cannot create an output file" "$binary" keygen "$tmpdir/missing/output.dat"
expect_failure "offlinekeys rejects invalid days" "$binary" offlinekeys "$tmpdir/offline.dat" "$keyfile" 7 not-a-number
expect_failure "regaddr rejects a missing address" "$binary" regaddr "$keyfile"
expect_failure "regaddralias rejects a missing address" "$binary" regaddralias "$keyfile" "$keyfile"
expect_failure "regaddr_3ld step1 rejects a missing address" "$binary" regaddr_3ld step1 "$keyfile"

printf 'PASS: CLI regression tests\n'
