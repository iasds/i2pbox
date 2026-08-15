#!/usr/bin/env bash
set -euo pipefail
# Corpus smoke run for the standalone fuzz drivers. No libFuzzer required
# (works with gcc in the local dev loop). Each corpus file is fed through
# LLVMFuzzerTestOneInput once; any crash/non-zero return fails the run.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
fails=0
for t in base64_decode b33address keyinfo routerinfo; do
    corpus="tests/fuzz/corpus/$t"
    [[ -d "$corpus" ]] || continue
    if ! ./tests/fuzz/fuzz_${t}_standalone "$corpus"/*; then
        echo "FAIL: fuzz_${t} standalone on corpus" >&2
        fails=1
    fi
done
if (( fails )); then
    exit 1
fi
echo "PASS: fuzz standalone smoke"
