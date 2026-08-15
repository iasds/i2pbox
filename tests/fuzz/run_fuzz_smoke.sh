#!/usr/bin/env bash
set -euo pipefail
# libFuzzer smoke run for CI: each target fuzzes its corpus for a short
# budget. A crash (non-zero exit) fails the run. Usage: run_fuzz_smoke.sh
# [seconds-per-target] (default 15).
seconds=${1:-15}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
fails=0
for t in base64_decode b33address keyinfo routerinfo; do
    corpus="tests/fuzz/corpus/$t"
    target="tests/fuzz/fuzz_${t}"
    echo "== $t (${seconds}s) =="
    if timeout "$((seconds + 15))" "$target" "$corpus" -max_total_time="$seconds" \
        -print_final_stats=1 >/tmp/fuzz-$t.log 2>&1; then
        echo "  ok"
    else
        rc=$?
        echo "  FAIL (exit $rc)" >&2
        tail -20 /tmp/fuzz-$t.log >&2
        fails=1
    fi
done
exit "$fails"
