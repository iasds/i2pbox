# Validation record: 2026-08 improvement batch

Every explicit requirement and every changed public output below maps to a
concrete check with its observed result. All checks ran locally on this
machine (x86_64, g++ 14.2.0, clang 19.1.7, OpenSSL 3.5.6) against commits
`3f9b4ed..e83b2d7` on top of `731a95a`; the only things not exercised here
are the GitHub Actions runs (the workflows were edited but not pushed).

## 1. Per-command help (feat 3f9b4ed, test d9694a8)

| Requirement / changed output | Check | Observed result |
|---|---|---|
| 11 commands (keygen keyinfo routerinfo regaddr regaddr_3ld i2pbase64 offlinekeys b33address regaddralias verifyhost autoconf_i2pd) accept `--help`, print usage, exit 0 | `tests/test_cli.sh` "help" group: `expect_ok "$c --help"` + `expect_match "^Usage: i2pbox ${c} "` | PASS (`make test`, 2026-08-15) |
| vain/x25519/famtool keep their own help | `vain --help`, `x25519 --help`, `famtool -h` exit 0 | PASS |
| `keygen --help` is a valid help flag, `--bogus` still rejected as filename | `expect_ok keygen --help`; `expect_failure keygen --bogus` | PASS |
| Top-level usage table unchanged | version/help groups | PASS |

## 2. Fuzzing (refactor 377ae8b, feat 2c60f4d, fix e83b2d7)

| Requirement / changed output | Check | Observed result |
|---|---|---|
| 4 libFuzzer targets build with clang | `make fuzz-build` (clang++, `-fsanitize=fuzzer,address,undefined`) | PASS: 4 binaries produced (2.2–56 MB) |
| Each target survives real fuzzing on its corpus | `tests/fuzz/run_fuzz_smoke.sh 10` | PASS: base64_decode, b33address, keyinfo, routerinfo all ok, 0 crashes |
| Shared decoder `decode_base64_string` is behavior-preserving | `make test` i2pbase64 group (vectors, CRLF, random roundtrip) | PASS |
| No memory errors under sanitizers | ASan+UBSan build + full `make test` (`detect_leaks=1 halt_on_error=1`) | PASS |
| Smoke scripts run the real corpus (not a silent skip) | repo-root resolution fixed (`../..`); standalone smoke reports PASS only when every corpus file runs | PASS (was a false PASS before e83b2d7) |
| CI has a fuzz-smoke job | `.github/workflows/ci.yml` contains `fuzz-smoke` job | present (not executed: not pushed) |
| Committed seeds are not polluted by fuzz runs | `run_fuzz_smoke.sh` fuzzes a temp copy; `git status tests/fuzz/corpus` clean except untracked artifacts | observed |

## 3. Security docs (docs e2d61ba)

| Requirement / changed output | Check | Observed result |
|---|---|---|
| SECURITY.md present | file exists, links to GitHub private reporting | observed |
| CONTRIBUTING.md present | file exists, documents dev loop + sanitizer flags | observed |
| README platform matrix is honest | "Platform support" table: Linux ✅/✅, macOS/FreeBSD/Windows ⚠️/❌ | observed |

## 4. Build fixes (build b0d94fc)

| Requirement / changed output | Check | Observed result |
|---|---|---|
| Bare `make` builds the whole project (not just main.o) | `.DEFAULT_GOAL := all`; `touch main.cpp && make` recompiles main.o and relinks | observed (was building only main.o before) |
| libi2pd.a update does not recompile objects | `touch i2pd/libi2pd.a && make -n`: 0 `-c`, 1 link | observed |
| Single-file change recompiles only that file | `touch main.cpp && make -n`: only `-o main.o` | observed |
| Full regression after clean rebuild | `make clean && make -j2 && make test` | PASS |

## 5. famtool password protection and validity (feat 22ecf88)

| Requirement / changed output | Check | Observed result |
|---|---|---|
| `-P` writes an encrypted private key | `head -2` of key shows `Proc-Type: 4,ENCRYPTED`; mode 0600 | observed |
| Encrypted PEM is standard OpenSSL format | `openssl ec -in key -passin pass:... -noout` exit 0 (correct pw), exit 1 (wrong pw), exit 1 (no pw) | observed |
| `-P` signs and `-V` verifies a protected family | `famtool -s ... -P` + `famtool -V ...` | PASS |
| Wrong password fails with non-zero exit | `expect_failure` + manual run: exit 1 | PASS |
| No password on encrypted key fails fast (no tty hang) | `expect_failure` + manual run: exit 1 immediately | PASS |
| `-e` sets validity, default 3650 | `openssl x509 -noout -dates`: notAfter = notBefore + 30d for `-e 30` | observed |
| `-e 0`, `-e abc` rejected | both exit 1 with "invalid validity days" | observed |
| Legacy unencrypted keys keep working | `famtool -g/-s/-V` without `-P` | PASS |
| Failed signing returns 1 and does not print "signed" | manual: "failed to sign router info", exit 1, no "signed" line | observed |
| `-g` refuses to overwrite an existing key or cert | repeat `famtool -g` on existing files: exit 1 "already exists"; fresh generation after removal works | PASS (was silent overwrite before; mirrors keygen) |

## 6. Incidental fixes folded into the batch

| Changed output | Check | Observed result |
|---|---|---|
| b33 store-hash test no longer date-dependent | assertion checks format; `make test` passes any day | PASS |
| fuzz smoke scripts resolve the repo root correctly | both scripts `cd dirname/../..`; both smoke runs exercise real files | observed |

## 7. Deep validation (extended fuzzing, 2026-08-15)

| Finding | Check | Observed result |
|---|---|---|
| routerinfo harness crashed on malformed input | 30s fuzz, exit 71 (ASan SEGV in `ByteStreamToBase64` + UBSan null `IdentityEx` call) | **harness bug, not product**: production `routerinfo` rejects the same input (`Error: Cannot read router info`); the harness touched `GetIdentHashBase64()` without the production `IsUnreachable()` gate. Fixed harness to mirror production. |
| b33address harness OOM on pathological input | 30s fuzz, `out-of-memory (used: 2064Mb)` | **harness bug**: no input-size cap; real destinations are ~600-char lines. Added a 1 MiB cap. Production reads a single stdin line (same behavior, no change). |
| OpenSSL 3 internal RSS growth in b33address | 20k-iteration runs: +1.8 KB/call; LSan reports nothing (objects reachable from OpenSSL globals) | **not i2pbox code, no leak report, no CLI impact**; `run_fuzz_smoke.sh` now passes `-rss_limit_mb=4096`. |
| Fixed harnesses survive extended fuzzing | `run_fuzz_smoke.sh 30` after fixes | PASS: all 4 targets, 30 s each, 0 crashes |

## 8. Additional validation (2026-08-15)

| Check | Observed result |
|---|---|
| `--help` anywhere in the arg list (`keygen --help foo`, `routerinfo -fp --help`) | exit 0, usage printed |
| famtool `-e` bounds: 36500 accepted, 36501 rejected | 0 / 1 |
| All three GitHub workflow files parse as YAML | OK; ci.yml jobs = test, fuzz-smoke |
| README example (`regaddr` host-record format) matches actual output | matches |
| All 10 commits GPG-signed, signatures verify | "Good signature" (iasds) |
| Commit contents contain no stray artifacts | diff stat: 35 files, 1513 insertions, 83 deletions, no binaries/.o |
| `-h` / `--help` / `help` at top level are equivalent | diff of the three outputs | identical |
| famtool `-P` is ignored by verify, `-e` ignored by sign | verify on signed router.info with `-P`: 0; sign with `-e`: 0 | PASS |
| `.specify/feature.json` parses and points at the restored dir | `json.load` + assert | valid |
| `make count` tolerates missing globs (`common/*.hpp`) | `make count` | fixed: exit 0 (was Error 1) |
