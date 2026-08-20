#!/usr/bin/env bash
set -euo pipefail
# libFuzzer smoke run for CI: each target fuzzes its corpus for a short
# budget. A crash (non-zero exit) fails the run. Usage: run_fuzz_smoke.sh
# [seconds-per-target] (default 15).
seconds=${1:-15}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
fails=0
# NOTE: routerinfo previously skipped due to ECDSAVerifier::Verify null EVP_PKEY
# crash on OpenSSL 3.0-3.4 (upstream i2pd #1997). Fixed locally in
# i2pd/libi2pd/Signature.cpp (early return when m_PublicKey is null); all
# four targets now run on every CI invocation. Remove this note if upstream
# merges the same guard.

for t in base64_decode b33address keyinfo routerinfo; do
    seeds="tests/fuzz/corpus/$t"
    target="tests/fuzz/fuzz_${t}"
    # fuzz in a temp copy of the corpus so newly discovered units (named by
    # sha1) never pollute the committed seed files
    tmpcorpus=$(mktemp -d)
    if [[ -d "$seeds" ]]; then
        cp -a "$seeds"/. "$tmpcorpus"/
    fi
    echo "== $t (${seconds}s) =="
    # -rss_limit_mb=4096: the b33address target runs BlindedPublicKey, whose
    # OpenSSL 3 internals grow RSS slowly (~1.8 KB/call, invisible to LSan,
    # not in i2pbox code). 4096 MB fits CI runners and comfortably covers the
    # smoke budget; single CLI runs are unaffected.
    if timeout "$((seconds + 15))" "$target" "$tmpcorpus" -max_total_time="$seconds" \
        -rss_limit_mb=4096 -print_final_stats=1 >/tmp/fuzz-$t.log 2>&1; then
        echo "  ok"
    else
        rc=$?
        echo "  FAIL (exit $rc)" >&2
        tail -20 /tmp/fuzz-$t.log >&2
        fails=1
    fi
    rm -rf "$tmpcorpus"
done
exit "$fails"
