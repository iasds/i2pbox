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

expect_clean_failure() {
    local description=$1
    shift
    local status
    if "$@" >"$tmpdir/stdout" 2>"$tmpdir/stderr"; then
        fail "$description succeeded"
    else
        status=$?
    fi
    if (( status >= 128 )); then
        fail "$description terminated by signal (exit $status)"
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

family_cert="$tmpdir/test-family.crt"
family_key="$tmpdir/test-family.pem"
"$binary" famtool -g -n testfamily -c "$family_cert" -k "$family_key" >"$tmpdir/famtool-generate.out"
printf 'not a router info' >"$tmpdir/invalid-router.info"
expect_clean_failure "famtool rejects an invalid router info" "$binary" famtool -V -n testfamily -c "$family_cert" -f "$tmpdir/invalid-router.info"

printf 'PASS: CLI regression tests\n'
