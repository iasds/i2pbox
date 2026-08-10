#!/usr/bin/env bash

# i2pbox CLI regression tests.
#
# Structure: one function per tool group, run in dependency order.
# Assertions prefer cross-tool interoperability (output of A verified by B)
# and golden vectors over exit-code-only checks.
#
# Usage: ./tests/test_cli.sh [i2pbox-binary] [gen-router-info-binary]

set -euo pipefail

binary=${1:-./i2pbox}
gen_router_info=${2:-./tests/gen_router_info}
vectors_dir="$(dirname "${BASH_SOURCE[0]}")/vectors"
timeout_s=60

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/i2pbox-tests.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

fails=0

fail() {
    fails=$((fails + 1))
    printf 'FAIL [%s]: %s\n' "$current_group" "$1" >&2
    if [[ -s "$tmpdir/stdout" ]]; then
        printf '  stdout:\n' >&2
        sed 's/^/    /' "$tmpdir/stdout" | tail -20 >&2
    fi
    if [[ -s "$tmpdir/stderr" ]]; then
        printf '  stderr:\n' >&2
        sed 's/^/    /' "$tmpdir/stderr" | tail -20 >&2
    fi
}

# run CMD... -> captures stdout/stderr, returns command exit code
run() {
    timeout "$timeout_s" "$@" >"$tmpdir/stdout" 2>"$tmpdir/stderr"
}

# NOTE: run "$@" || status=$? is used (not `if ! run; then status=$?`) because
# $? inside the if-branch reports the if-structure's result, not the command's
# exit code. The || pattern is also set -e / pipefail safe.
expect_ok() {
    local description=$1 status=0
    shift
    run "$@" || status=$?
    if (( status != 0 )); then
        fail "$description (exit $status)"
        return 1
    fi
    return 0
}

expect_failure() {
    local description=$1 status=0
    shift
    run "$@" || status=$?
    if (( status == 0 )); then
        fail "$description succeeded"
        return 1
    fi
    return 0
}

expect_clean_failure() {
    local description=$1 status=0
    shift
    run "$@" || status=$?
    if (( status == 0 )); then
        fail "$description succeeded"
        return 1
    fi
    if (( status >= 128 )); then
        fail "$description terminated by signal (exit $status)"
        return 1
    fi
    return 0
}

expect_match() {
    local description=$1 pattern=$2 file=$3
    if ! grep -qE "$pattern" "$file"; then
        fail "$description (pattern: $pattern)"
        return 1
    fi
    return 0
}

# hex input -> raw bytes on stdout (no dependency on xxd)
hex_to_bin() {
    python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))'
}

# assert that every line of the file is valid I2P base64
# (python is used because GNU grep's $-anchored regexes fail on lines > ~530 chars)
expect_base64_lines() {
    local description=$1 file=$2
    if ! python3 - "$file" <<'PY'
import sys
alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~=")
lines = [l.rstrip("\r\n") for l in open(sys.argv[1]) if l.strip()]
ok = all(set(l) <= alphabet for l in lines)
sys.exit(0 if ok else 1)
PY
    then
        fail "$description (contains non-I2P-base64 characters)"
        return 1
    fi
    return 0
}

group() {
    current_group=$1
    printf '== %s\n' "$1"
}

###############################################################################
# version
###############################################################################

group "version"
expect_ok "--version exits cleanly" "$binary" --version
expect_match "--version identifies i2pbox and i2pd" 'i2pbox.*i2pd' "$tmpdir/stdout"
expect_failure "no arguments exits non-zero" "$binary"
expect_ok "help exits cleanly" "$binary" help
expect_match "help lists all 14 commands" 'vain|keygen|keyinfo|famtool|routerinfo|regaddr|regaddr_3ld|i2pbase64|offlinekeys|b33address|regaddralias|x25519|verifyhost|autoconf_i2pd' "$tmpdir/stdout"

###############################################################################
# keygen
###############################################################################

group "keygen"
keyfile="$tmpdir/identity.dat"
expect_ok "keygen EdDSA" "$binary" keygen "$keyfile" 7
test -s "$keyfile" || fail "keygen did not create a key file"
test "$(stat -c '%a' "$keyfile")" = "600" || fail "keygen did not create a 0600 key file"
expect_match "keygen reports the b32 destination" '^Destination [a-z2-7]{52} created$' "$tmpdir/stdout"
expect_match "keygen reports the signature type" 'Signature type: ED25519-SHA512 \(7\)' "$tmpdir/stdout"

keyfile_red="$tmpdir/reddsa.dat"
expect_ok "keygen RedDSA" "$binary" keygen "$keyfile_red" 11
expect_match "keygen RedDSA reports type" 'RED25519-SHA512 \(11\)' "$tmpdir/stdout"

keyfile_p521="$tmpdir/p521.dat"
expect_ok "keygen ECDSA-P521" "$binary" keygen "$keyfile_p521" 3
expect_match "keygen P521 reports type" 'ECDSA-P521 \(3\)' "$tmpdir/stdout"

keyfile_dsa="$tmpdir/dsa.dat"
expect_ok "keygen DSA" "$binary" keygen "$keyfile_dsa" 0
expect_match "keygen DSA reports type" 'DSA-SHA1 \(0\)' "$tmpdir/stdout"

expect_failure "keygen cannot create in a missing directory" "$binary" keygen "$tmpdir/missing/output.dat"
expect_failure "keygen rejects an unknown signature type" "$binary" keygen "$tmpdir/bad.dat" 99
expect_failure "keygen rejects a garbage signature type name" "$binary" keygen "$tmpdir/bad.dat" no-such-type

expect_ok "keygen RSA-SHA256 name resolves and falls back" "$binary" keygen "$tmpdir/rsa.dat" RSA-SHA256
if ! grep -q 'RSA signature type is not supported' "$tmpdir/stderr"; then
    fail "RSA-SHA256 name did not warn about the fallback"
fi

###############################################################################
# keyinfo
###############################################################################

group "keyinfo"
expect_ok "keyinfo on generated EdDSA key" "$binary" keyinfo "$keyfile"
expect_match "keyinfo default output is a b32 address" '^[a-z2-7]{52}\.b32\.i2p$' "$tmpdir/stdout"

# note: the Destination base64 line is ~537 chars; GNU grep's $-anchored
# regexes can fail on such long lines, so match the prefix separately and
# check the padding suffix in the shell (no $ anchor)
expect_ok "keyinfo -v on generated EdDSA key" "$binary" keyinfo -v "$keyfile"
expect_match "keyinfo -v shows Destination" '^Destination: ' "$tmpdir/stdout"
dest_line=$(grep '^Destination: ' "$tmpdir/stdout" | head -1 || true)
if [[ $dest_line != "Destination: "* || $dest_line != *"==" ]]; then
    fail "keyinfo -v Destination is not I2P base64"
fi
expect_match "keyinfo -v shows Destination Hash" '^Destination Hash: [A-Za-z0-9~-]+=+$' "$tmpdir/stdout"
expect_match "keyinfo -v shows B32 Address" '^B32 Address: [a-z2-7]{52}\.b32\.i2p$' "$tmpdir/stdout"
expect_match "keyinfo -v shows signature type" '^Signature Type: ED25519-SHA512$' "$tmpdir/stdout"
expect_match "keyinfo -v shows encryption type" '^Encryption Type: 0$' "$tmpdir/stdout"

expect_ok "keyinfo -v on RedDSA key" "$binary" keyinfo -v "$keyfile_red"
expect_match "keyinfo -v RedDSA signature type" '^Signature Type: RED25519-SHA512$' "$tmpdir/stdout"

expect_ok "keyinfo -p prints the private key" "$binary" keyinfo -p "$keyfile"
expect_base64_lines "keyinfo -p output is I2P base64" "$tmpdir/stdout"
# -p output is a single ~900-char line; check the padding via the file tail
# (tail -c 2 of "...==\n" is "=\n") instead of a $-anchored regex
if ! tail -c 2 "$tmpdir/stdout" | grep -q '='; then
    fail "keyinfo -p output does not end in padding"
fi

expect_failure "keyinfo rejects a missing file" "$binary" keyinfo "$tmpdir/does-not-exist.dat"
printf 'garbage' >"$tmpdir/garbage.dat"
expect_failure "keyinfo rejects a garbage key file" "$binary" keyinfo "$tmpdir/garbage.dat"

# golden vector: fixed key, b32 independently derived (SHA-256 -> base32)
expect_ok "keyinfo on the fixed vector key" "$binary" keyinfo "$vectors_dir/ed25519.keys"
expect_match "b32 matches the independently derived vector" "^$(cat "$vectors_dir/ed25519.b32")$" "$tmpdir/stdout"
expect_ok "keyinfo -d on the fixed vector key" "$binary" keyinfo -d "$vectors_dir/ed25519.keys"
if ! grep -F -q "$(cat "$vectors_dir/ed25519.dest")" "$tmpdir/stdout"; then
    fail "destination does not match the vector"
fi

###############################################################################
# offlinekeys
###############################################################################

group "offlinekeys"
offlinefile="$tmpdir/offline.dat"
expect_ok "offlinekeys generates offline keys" "$binary" offlinekeys "$offlinefile" "$keyfile" 7 1
test -s "$offlinefile" || fail "offlinekeys did not create a key file"
test "$(stat -c '%a' "$offlinefile")" = "600" || fail "offlinekeys did not create a 0600 key file"

expect_ok "keyinfo reads the offline key" "$binary" keyinfo -v "$offlinefile"
expect_match "keyinfo reports offline signature" 'Offline signature' "$tmpdir/stdout"
expect_match "keyinfo reports expiry" '^Expires: ' "$tmpdir/stdout"
expect_match "keyinfo reports transient signature type" '^Transient Signature Type: ' "$tmpdir/stdout"

expect_failure "offlinekeys rejects invalid days" "$binary" offlinekeys "$tmpdir/offline.dat" "$keyfile" 7 not-a-number
expect_failure "offlinekeys rejects a bad master key" "$binary" offlinekeys "$tmpdir/offline.dat" "$tmpdir/garbage.dat" 7 30

###############################################################################
# i2pbase64
###############################################################################

group "i2pbase64"
while read -r hex expected; do
    [[ $hex == \#* || -z $hex ]] && continue
    if ! printf '%s' "$hex" | hex_to_bin | run "$binary" i2pbase64; then
        fail "encode vector $hex -> $expected (i2pbase64 failed)"
        continue
    fi
    if ! grep -qx "$expected" "$tmpdir/stdout"; then
        fail "encode vector $hex -> $expected (got: $(cat "$tmpdir/stdout"))"
    fi
done < "$vectors_dir/i2pbase64.vectors"

while read -r hex expected; do
    [[ $hex == \#* || -z $hex ]] && continue
    if ! printf '%s' "$expected" | run "$binary" i2pbase64 -d; then
        fail "decode vector $expected -> $hex (i2pbase64 failed)"
        continue
    fi
    if ! printf '%s' "$hex" | hex_to_bin | cmp -s - "$tmpdir/stdout"; then
        fail "decode vector $expected -> $hex"
    fi
done < "$vectors_dir/i2pbase64.vectors"

# roundtrip on random bytes
head -c 2048 /dev/urandom >"$tmpdir/random.bin"
expect_ok "base64 roundtrip: encode random data" "$binary" i2pbase64 "$tmpdir/random.bin"
cp "$tmpdir/stdout" "$tmpdir/random.b64"
expect_ok "base64 roundtrip: decode random data" "$binary" i2pbase64 -d "$tmpdir/random.b64"
cp "$tmpdir/stdout" "$tmpdir/random.out"
cmp -s "$tmpdir/random.bin" "$tmpdir/random.out" || fail "base64 roundtrip mismatch on random data"

expect_failure "i2pbase64 rejects an invalid input alphabet" bash -c "printf '!!!' | '$binary' i2pbase64 -d"

###############################################################################
# x25519
###############################################################################

group "x25519"
expect_ok "x25519 generates a key pair" "$binary" x25519
expect_match "x25519 prints a public key" '^PublicKey: [A-Za-z0-9~-]+=+$' "$tmpdir/stdout"
expect_match "x25519 prints a private key" '^PrivateKey: [A-Za-z0-9~-]+=+$' "$tmpdir/stdout"

###############################################################################
# vain
###############################################################################

group "vain"
expect_ok "vain finds a short prefix" "$binary" vain ej -t 2 -o "$tmpdir/vain.dat"
vain_out=$(ls "$tmpdir"/vain.dat*.dat 2>/dev/null | head -1 || true)
test -n "$vain_out" || fail "vain did not create an output file"
expect_ok "vain output is a valid key" "$binary" keyinfo -v "$vain_out"
expect_match "vain output starts with the prefix" "^B32 Address: ej[a-z2-7]{50}\.b32\.i2p$" "$tmpdir/stdout"

# regex mode uses std::regex_match against the full 52-char b32 address
expect_ok "vain regex mode" "$binary" vain '[a-z]{4}[a-z2-7]{48}' -r -t 2 -o "$tmpdir/vain-regex.dat"
vain_regex_out=$(ls "$tmpdir"/vain-regex.dat*.dat 2>/dev/null | head -1 || true)
test -n "$vain_regex_out" || fail "vain regex did not create an output file"
expect_ok "vain regex output is a valid key" "$binary" keyinfo -v "$vain_regex_out"

expect_failure "vain rejects a missing pattern" "$binary" vain

###############################################################################
# regaddr
###############################################################################

group "regaddr"
expect_ok "regaddr generates a host record" "$binary" regaddr "$keyfile" myname.i2p
host_record=$(cat "$tmpdir/stdout")
# note: destination base64 ends with == before #!sig=, so the char class must
# include '=' (and the line is ~630 chars, so no trailing $ anchor)
printf '%s\n' "$host_record" | grep -qE '^myname\.i2p=[A-Za-z0-9~=-]+#!sig=[A-Za-z0-9~=-]+' \
    || fail "regaddr output format: got ${host_record:0:40}..."

expect_failure "regaddr rejects a missing address" "$binary" regaddr "$keyfile"
expect_failure "regaddr rejects a bad key file" "$binary" regaddr "$tmpdir/garbage.dat" myname.i2p

###############################################################################
# regaddr_3ld
###############################################################################

group "regaddr_3ld"
parent_key="$tmpdir/parent.dat"
expect_ok "regaddr_3ld needs a parent key" "$binary" keygen "$parent_key" 7
expect_ok "regaddr_3ld step1" "$binary" regaddr_3ld step1 "$keyfile" blog.myname.i2p
test -s "$tmpdir/stdout" || fail "regaddr_3ld step1 produced no output"
step1=$(cat "$tmpdir/stdout")
expect_ok "regaddr_3ld step2" "$binary" regaddr_3ld step2 <(printf '%s' "$step1") "$parent_key" myname.i2p
step2=$(cat "$tmpdir/stdout")
test -n "$step2" || fail "regaddr_3ld step2 produced no output"
expect_ok "regaddr_3ld step3" "$binary" regaddr_3ld step3 <(printf '%s' "$step2") "$keyfile"
test -n "$(cat "$tmpdir/stdout")" || fail "regaddr_3ld step3 produced no output"
expect_failure "regaddr_3ld step1 rejects a missing address" "$binary" regaddr_3ld step1 "$keyfile"
expect_failure "regaddr_3ld rejects an unknown step" "$binary" regaddr_3ld step9 "$keyfile" foo.i2p

###############################################################################
# regaddralias
###############################################################################

group "regaddralias"
new_keyfile="$tmpdir/new.dat"
expect_ok "regaddralias needs a fresh key" "$binary" keygen "$new_keyfile" 7
expect_ok "regaddralias generates an alias record" "$binary" regaddralias "$keyfile" "$new_keyfile" myname.i2p
alias_record=$(cat "$tmpdir/stdout")
printf '%s\n' "$alias_record" | grep -qE 'olddest=[A-Za-z0-9~-]+.*oldsig=[A-Za-z0-9~-]+' \
    || fail "regaddralias output format: got ${alias_record:0:40}..."
expect_failure "regaddralias rejects a missing address" "$binary" regaddralias "$keyfile" "$new_keyfile"

###############################################################################
# verifyhost (incl. the olddest branch covered by regaddralias)
###############################################################################

group "verifyhost"
expect_ok "verifyhost accepts a regaddr record" "$binary" verifyhost "$host_record"
expect_failure "verifyhost rejects a tampered record" "$binary" verifyhost "${host_record%?}X"
expect_ok "verifyhost accepts a regaddralias record" "$binary" verifyhost "$alias_record"
expect_failure "verifyhost rejects garbage" "$binary" verifyhost "not-a-record"

###############################################################################
# b33address
###############################################################################

group "b33address"
expect_ok "b33address from the fixed EdDSA vector" "$binary" keyinfo -d "$vectors_dir/ed25519.keys"
expected_b33=$(sed -n 1p "$vectors_dir/ed25519.b33")
expected_hash=$(sed -n 2p "$vectors_dir/ed25519.b33")
b33_dest=$(cat "$tmpdir/stdout")
if ! printf '%s' "$b33_dest" | run "$binary" b33address; then
    fail "b33address from the fixed EdDSA vector failed"
    b33_out=
else
    b33_out=$(cat "$tmpdir/stdout")
fi
printf '%s\n' "$b33_out" | grep -q "^b33 address: ${expected_b33}$" || fail "b33 address mismatch (got: $b33_out)"
printf '%s\n' "$b33_out" | grep -q "^Today's store hash: ${expected_hash}$" || fail "b33 store hash mismatch (got: $b33_out)"

expect_ok "b33address from the fixed RedDSA vector" "$binary" keyinfo -d "$vectors_dir/reddsa.keys"
expected_red=$(sed -n 1p "$vectors_dir/reddsa.b33")
b33_red_dest=$(cat "$tmpdir/stdout")
if ! printf '%s' "$b33_red_dest" | run "$binary" b33address; then
    fail "b33address from the fixed RedDSA vector failed"
    b33_red=
else
    b33_red=$(cat "$tmpdir/stdout")
fi
printf '%s\n' "$b33_red" | grep -q "^b33 address: ${expected_red}$" || fail "RedDSA b33 address mismatch"

# keyinfo -b must agree with the b33address tool
expect_ok "keyinfo -b on the fixed vector key" "$binary" keyinfo -b "$vectors_dir/ed25519.keys"
expect_match "keyinfo -b b33 matches the b33address tool" "^b33 address: ${expected_b33}$" "$tmpdir/stdout"

###############################################################################
# famtool
###############################################################################

group "famtool"
family_cert="$tmpdir/test-family.crt"
family_key="$tmpdir/test-family.pem"
expect_ok "famtool generates a family key" "$binary" famtool -g -n testfamily -c "$family_cert" -k "$family_key"
test -s "$family_cert" || fail "famtool did not create the certificate"
test -s "$family_key" || fail "famtool did not create the private key"
test "$(stat -c '%a' "$family_key")" = "600" || fail "famtool did not create a 0600 family key"

printf 'not a router info' >"$tmpdir/invalid-router.info"
expect_clean_failure "famtool rejects an invalid router info" "$binary" famtool -V -n testfamily -c "$family_cert" -f "$tmpdir/invalid-router.info"

expect_ok "famtool generates a valid router.info" "$gen_router_info" "$keyfile" "$tmpdir/router.info"
expect_ok "famtool signs a router.info" "$binary" famtool -s -n testfamily -k "$family_key" -i "$keyfile" -f "$tmpdir/router.info"
expect_ok "famtool verifies the signed router.info" "$binary" famtool -V -n testfamily -c "$family_cert" -f "$tmpdir/router.info"
expect_match "famtool reports verified" '^verified$' "$tmpdir/stdout"
expect_clean_failure "famtool rejects the wrong family" "$binary" famtool -V -n wrongfamily -c "$family_cert" -f "$tmpdir/router.info"
expect_clean_failure "famtool rejects the wrong certificate" "$binary" famtool -V -n testfamily -c "$family_key" -f "$tmpdir/router.info"

# signed router.info must still parse as a valid router
expect_ok "signed router.info is still parseable" "$binary" routerinfo "$tmpdir/router.info"
expect_match "signed router.info reports a hash" '^Router Hash: [A-Za-z0-9~=-]+=+$' "$tmpdir/stdout"

###############################################################################
# routerinfo
###############################################################################

group "routerinfo"
expect_ok "routerinfo parses a non-published router.info" "$binary" routerinfo "$tmpdir/router.info"
expect_match "routerinfo reports a hash" '^Router Hash: [A-Za-z0-9~=-]+=+$' "$tmpdir/stdout"

# only a published router.info carries the NTCP2 address section
expect_ok "routerinfo generates a published router.info" "$gen_router_info" "$keyfile" "$tmpdir/published.info" 1.2.3.4
expect_ok "routerinfo parses the published router.info" "$binary" routerinfo "$tmpdir/published.info"
expect_match "routerinfo shows the NTCP2 address" '^NTCP2: 1\.2\.3\.4$' "$tmpdir/stdout"

expect_ok "routerinfo -fp emits iptables rules" "$binary" routerinfo -fp "$tmpdir/published.info"
expect_match "routerinfo -fp emits an ACCEPT rule" ' -A OUTPUT -p tcp -d 1\.2\.3\.4 --dport 12345 -j ACCEPT' "$tmpdir/stdout"

expect_failure "routerinfo rejects garbage" "$binary" routerinfo "$tmpdir/garbage.dat"
expect_failure "routerinfo rejects a missing file" "$binary" routerinfo "$tmpdir/nope.info"

###############################################################################
# autoconf_i2pd (non-interactive: feed answers on stdin)
###############################################################################

group "autoconf_i2pd"
# non-interactive: feed answers on stdin; the tool emits CRLF line endings and
# grep -E cannot express \r, so strip CR before matching
if ! printf 'en\n2\n4\n5\n12345\n1\n1\n1\nN\nN\nN\n' | run "$binary" autoconf_i2pd; then
    fail "autoconf_i2pd exited non-zero"
fi
if grep -qiE 'error|exception|panic|terminat' "$tmpdir/stderr"; then
    fail "autoconf_i2pd failed with errors: $(head -3 "$tmpdir/stderr")"
fi
tr -d '\r' < "$tmpdir/stdout" | grep -qE '^daemon=true$' \
    || fail "autoconf_i2pd does not emit daemon=true"

###############################################################################

if (( fails > 0 )); then
    printf '\nFAIL: %d test group(s) failed\n' "$fails" >&2
    exit 1
fi
printf 'PASS: CLI regression tests\n'
