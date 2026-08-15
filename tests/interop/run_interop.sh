#!/usr/bin/env bash
# Interop validation: cross-validate i2pbox outputs against independent I2P
# implementations (go-i2p, emissary, i2p-java) in addition to the bundled
# i2pd regression suite.
#
# Usage: ./tests/interop/run_interop.sh [i2pbox-binary] [implementations...]
#   implementations: go rust java (default: all available)
#
# Requires: go, cargo, javac (as needed). i2p-java uses net.i2p:i2p from
# Maven Central (downloaded to $I2P_JAR or $tmpdir).
set -euo pipefail

binary=${1:-./i2pbox}
want=${2:-go rust java}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/i2pbox-interop.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
fails=0

fail() {
    fails=$((fails + 1))
    printf 'FAIL [interop %s]: %s\n' "$current_impl" "$1" >&2
}

# --- produce i2pbox artifacts ------------------------------------------------
# gen_router_info is a test helper built from source; build it if a caller
# invokes this script directly (without the make interop target).
if [[ ! -x tests/gen_router_info ]]; then
    make tests/gen_router_info >/dev/null 2>&1 || {
        echo "cannot build tests/gen_router_info" >&2
        exit 1
    }
fi
"$binary" keygen "$tmpdir/router.keys" 7 >/dev/null 2>&1
dest=$("$binary" keyinfo -d "$tmpdir/router.keys")
b32=$("$binary" keyinfo "$tmpdir/router.keys")
hash=$("$binary" keyinfo -v "$tmpdir/router.keys" | awk '/^Destination Hash: /{print $3}')
./tests/gen_router_info "$tmpdir/router.keys" "$tmpdir/router.info"
ri_hash=$("$binary" routerinfo "$tmpdir/router.info" | awk '/^Router Hash: /{print $3}')

# --- go-i2p ------------------------------------------------------------------
run_go() {
    current_impl=go
    local bin="$tmpdir/interop_go"
    (cd tests/interop/go && go build -o "$bin" .) >/dev/null 2>&1 || {
        fail "go verifier build failed"; return 1; }
    [[ "$("$bin" base64-encode 48656c6c6f)" == "SGVsbG8=" ]] || fail "base64 encode"
    "$bin" base64-decode SGVsbG8gd29ybGQ= 48656c6c6f20776f726c64 || fail "base64 decode"
    "$bin" destination "$dest" "$b32" "$hash" || fail "destination/b32/hash"
    "$bin" router-info "$tmpdir/router.info" || fail "router.info parse+verify"
    echo "  go-i2p: ok"
}

# --- emissary (Rust) ----------------------------------------------------------
run_rust() {
    current_impl=rust
    local bin="tests/interop/rust/target/release/interop-rust"
    (cd tests/interop/rust && cargo build --release -q) >/dev/null 2>&1 || {
        fail "rust verifier build failed"; return 1; }
    # exit 2 = emissary capability limit (X25519-only identities), SKIP
    rc=0
    "$bin" router-identity "$tmpdir/router.info" "$ri_hash" || rc=$?
    if (( rc == 0 )); then
        echo "  emissary: ok"
    elif (( rc == 2 )); then
        echo "  emissary: SKIP (capability limit)"
    else
        fail "router identity hash"
    fi
}

# --- i2p-java -----------------------------------------------------------------
run_java() {
    current_impl=java
    local jar="${I2P_JAR:-}"
    if [[ -z "$jar" ]]; then
        jar="$tmpdir/i2p-2.13.0.jar"
        curl -fsSL -o "$jar" \
            "https://repo1.maven.org/maven2/net/i2p/i2p/2.13.0/i2p-2.13.0.jar" \
            >/dev/null 2>&1 || { fail "i2p jar download failed"; return 1; }
    fi
    (cd tests/interop/java && javac -cp "$jar" InteropJava.java) >/dev/null 2>&1 || {
        fail "java verifier build failed"; return 1; }
    local cp="tests/interop/java:$jar"
    [[ "$(java -cp "$cp" InteropJava base64-encode 48656c6c6f)" == "SGVsbG8=" ]] || fail "base64 encode"
    java -cp "$cp" InteropJava base64-decode SGVsbG8gd29ybGQ= 48656c6c6f20776f726c64 || fail "base64 decode"
    java -cp "$cp" InteropJava destination "$dest" "$b32" "$hash" || fail "destination/b32/hash"
    echo "  i2p-java: ok"
}

for impl in $want; do
    case "$impl" in
        go)   run_go ;;
        rust) run_rust ;;
        java) run_java ;;
        *)    echo "unknown implementation: $impl (want: go rust java)" >&2 ;;
    esac
done

if (( fails > 0 )); then
    printf 'FAIL: %d interop check(s) failed\n' "$fails" >&2
    exit 1
fi
echo "PASS: interop validation"
