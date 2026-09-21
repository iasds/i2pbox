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

## 9. H-04 closure batch (2026-08-22, commits ce04239..ce17f7e)

| Requirement / changed output | Check | Observed result |
|---|---|---|
| Audit H-04: vain threaded search is race-free | ThreadSanitizer build (`make build-tsan`), 6 manual runs incl. 10-min hard-prefix + full CLI suite against the TSan binary | PASS: zero TSan reports |
| vain `-m` stops cleanly on SIGINT, no mid-write truncation | suite: run 3s, `kill -INT`, wait; also under ASan+UBSan+LSan and TSan | exit 0, summary printed, no sanitizer findings |
| vain `-m` does not spam files when a round finds nothing | suite asserts finite file set == produced keys; sequential names mm.datN.dat | PASS (was: tens of thousands of files) |
| Every `-m` key file is valid | suite: `keyinfo` on each produced file | PASS |
| `i2pbox help <command>` prints per-command usage | all 14 commands verified individually + suite assertions | PASS: usage line or native help; unknown subcommand exits 1 |
| Version strings carry no `-dirty` | submodule guard committed on iasds/i2pd `openssl-patched` (bf4b156); `.gitmodules` URL points at the fork so CI can fetch the pin | `v2.0.1-25-gce17f7e (i2pd bf4b156)` |
| Submodule pin fetchable by CI | first push failed checkout with `upload-pack: not our ref bf4b156`; after ce17f7e the pin resolves from the fork | fixed in same push cycle |
| Full remote CI green | run 32548643833 on ce17f7e: test(normal) 2m03s, test(sanitizers) 3m36s, fuzz-smoke 5m04s, cppcheck 33s, interop(go-i2p/emissary) 3m08s | all ✓ |
| Packaging still intact after changes | `make install DESTDIR=... PREFIX=/usr`: bin 0755 + bash/zsh completions; installed binary runs version/help | PASS |
| All commits GPG-signed | `git log --show-signature` over the batch | Good signature (iasds) |

## 10. b33offlinekeys batch (2026-09-21, worktree on top of 4d16e6e)

Port of upstream PurpleI2P/i2pd-tools `b33offlinekeys` (PR #124): per-day keys
for an encrypted LeaseSet, appended after the offline-signed online keys;
`keyinfo -b` reports the batch span via the new `common/b33_offline.hpp`
reader. All checks ran locally on this machine (x86_64, g++ 14.2.0,
clang 19, OpenSSL 3.5.7). Interop was not re-run locally: it exercises only
`keyinfo -d`/bare/`-v` and `offlinekeys`, whose outputs are byte-identical
(no batch present → no new line); CI covers it on push.

| Requirement / changed output | Check | Observed result |
|---|---|---|
| 15th subcommand builds with zero new warnings | `make clean && make -j2` | PASS; only pre-existing autoconf_i2pd.cpp Cyrillic-switch warning |
| Full regression incl. the new b33offlinekeys group | `make test` | PASS |
| ASan/UBSan/leak-clean under the CI sanitizer flags | sanitizer `make -j6` + `make test` with `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1` | PASS |
| Batch-tail parser has a fuzz target mirroring the `keyinfo -b` path | `tests/fuzz/fuzz_b33offline.cpp` + committed seed `tests/fuzz/corpus/b33offline/ed25519-batch.keys`, wired into `fuzz-build`, both smoke scripts, `.gitignore` | present |
| All libFuzzer targets build (clang++-19, fuzzer+ASan+UBSan) | `make fuzz-build FUZZ_CC=clang++-19` | PASS: 6/6 binaries, 0 warnings |
| libFuzzer smoke incl. the new target | `tests/fuzz/run_fuzz_smoke.sh 15` | PASS: all 6 targets ok, 0 crashes |
| gcc standalone smoke, normal and sanitizer builds | `make fuzz-smoke` (plain; then ASan/UBSan `CXXFLAGS`/`LDFLAGS`) | PASS both |
| Perf baseline | `make bench` | keygen 1080 ms / keyinfo -v 732 ms / base64-rt 624 ms per 100x, vain smoke ok |
| `.specify/feature.json` dangling pointer | specs/ unpublished + gitignored since 8720c4c, absent even locally | removed (repo no longer tracks `.specify/`) |
| `.gitignore` fuzz binaries | `tests/fuzz/fuzz_verifyhost` was never ignored (pre-existing gap) | added alongside `fuzz_b33offline` |

## 11. b33offlinekeys day-cap fix and fuzz-seed lifetime (2026-09-21, follow-up review)

An independent review of section 10 found that the port kept upstream's
65,535-day cap, which exceeds the 32-bit expiry format: past
`(UINT32_MAX - now) / 86400` days the per-day expiries wrap into the past and
the written file is rejected by every reader (its inner offline signature
reads as expired), while the command still reported success. The committed
fuzz seed had the mirror-image problem: a 2-day batch whose offline signature
expired on 2026-09-22, after which `FromBuffer` returns 0 and
`fuzz_b33offline` returns before reaching the batch parser, silently losing
that coverage. All checks ran locally on this machine (x86_64, g++ 14.2.0,
clang 19, OpenSSL 3.5.7).

| Requirement / changed output | Check | Observed result |
|---|---|---|
| Days past the uint32 expiry horizon are rejected up front | `i2pbox b33offlinekeys out keys 65535` → exit 6, `days must be an integer between 1 and 28992`; `70000`, `28994`, `28993`, cap+1 also exit 6 | PASS |
| Out-of-range counts cannot slip through the `unsigned` → `int` conversion | `4294967295`, `2147483648`, `2147483647`, `4000000`, `-1`, `0`, `not-a-number` all exit 6; `2` and the cap `28992` exit 0 | PASS |
| The defect is reproducible on the pre-fix code | pre-fix `b33offlinekeys.o` relinked into a scratch binary: `65535` exits 0 and writes 8 782 538 bytes, `keyinfo -b` on it prints no span (the tail no longer parses), `keyinfo -v` reports the wrapped inner expiry `18/01/2070` instead of 2106, and the entries from day 28993 on carry expiries in 1970; `28994` also exits 0 but writes a file `keyinfo -v` rejects with exit 3 `bad key file format` | reproduced |
| The new tests fail against the pre-fix binary | `tests/test_cli.sh <pre-fix binary>` | FAIL `b33offlinekeys rejects the old 16-bit cap succeeded` |
| The cap tracks the epoch rather than a constant | suite cross-checks the reported cap against `(2**32 - 1 - time.time()) // 86400`, tolerance 1 day | PASS |
| The accepted maximum still yields a valid batch | `b33offlinekeys out keys 28992` + independent verifier: every per-day blinded RedDSA signature verifies against that day's blinded public key, transient keypairs consistent, last day 21060205 == inner offline-signature expiry | PASS (17.7 s, 3.9 MB) |
| A batch generated at the horizon is loadable | `keyinfo -b` on the 28992-day file reports `28992 days, 20260921 to 21060205`; `keyinfo -v` exits 0 | PASS |
| Committed fuzz seed outlives the review | regenerated with `days=2000` (268 848 bytes, valid to 2032-03-12); verifier: all 2000 signatures verify | PASS |
| Seed expiry can no longer go unnoticed | `make test` asserts the seed still loads, still carries a batch span, and keeps at least 90 days of validity, with a regeneration hint | PASS |
| `keyinfo -p` does not silently drop a batch tail | documented on the `keyinfo` option row and in the b33offlinekeys section (the pinned libi2pd cannot re-emit the tail) | observed |
| Stale command counts | `README.md` said 14 subcommands/binaries in three places; upstream now builds 15 (b33offlinekeys merged) | fixed |
| No new warnings | `make -j2` after the fix | PASS; only the pre-existing autoconf_i2pd warnings |
| Full regression after the fix | `make test` | PASS (11.0 s) |

## 12. Cross-validation against upstream i2pd-tools (2026-09-21)

The batch format is shared with upstream, so section 10/11 were re-checked by
generating the same destinations' batches with both implementations and
cross-reading them, including the router-side consumer. Upstream side:
PurpleI2P/i2pd-tools master `39f45c6` (2026-09-16, the PR #124 merge) built
against `freeacetone/i2pd` branch `b33-offline-keys` `fad677b` (2026-09-17),
the only libi2pd that carries the `B33OfflineKeys` support the tools expect.

| Requirement / changed output | Check | Observed result |
|---|---|---|
| Upstream master builds with its own pinned submodule | clean clone, pinned i2pd `80080fd` (2025-10-15), `make b33offlinekeys keyinfo` | FAILS: 9 compile errors (`B33_OFFLINE_KEYS_VERSION`/`_HEADER_LENGTH`, `SECONDS_PER_DAY`, `OFFLINE_SIGNATURE_HEADER_LENGTH`, `GetB33OfflineKeys` all missing) — upstream needs a submodule bump; ours defines the constants locally for the same reason |
| Same keys and day counts produce interoperable files | 3 cases (Ed25519 5 d, RedDSA 1 d, Ed25519 365 d via the default path), both tools' output compared field by field | PASS 45/45 checks: identical file sizes and byte-identical deterministic structure (header, per-day expires/date/sig type, entry length), identical stdout |
| Each side can read the other's file | `i2pbox keyinfo -b` on the upstream file, upstream `keyinfo -b` on ours, bare `keyinfo` b32 both ways | PASS: same span and same b32 from both readers |
| Blinded derivation agrees across libi2pd versions | every file verified by both the pinned libi2pd (2.61.0, `Blinding.cpp` Ed25519/RedDSA) and the reference branch: per-day blinded signature vs the day's blinded public key, transient keypair consistency | PASS: both files, both derivations, all days |
| Router-side load and re-serialize | reference `PrivateKeys::FromBuffer` → `GetB33OfflineKeys` → `ToBuffer` on both tools' files | PASS: batch preserved, round trip byte-identical |
| The batch is actually usable per day | reference `BlindedPrivateKey::Create` + `CreateSigner(day)` for every day, verified the way a LeaseSet client does (transient-key signature plus the carried offline blob authorized by that day's blinded key) | PASS: 5/5, 1/1 and 365/365 days; days outside the batch return a null signer |
| Malformed batch handled safely | truncating the last day, inflating the day count to 65535, randomizing the tail, flipping the ident hash | i2pbox: no span, exit 0, ASan-clean, and the consumer refuses to sign. Upstream `keyinfo`: `heap-buffer-overflow` under ASan (READ of size 4 in `buf32toh`) and a bogus span `20260921 to 19691231` on the truncated file |
| That bounds check is test-covered | bounds-check-free copy of `common/b33_offline.hpp` linked into `keyinfo`, run under ASan | suite FAILS at `keyinfo -b ignores a truncated batch` with the heap-buffer-overflow; the real build passes |
| Adversarial batches are a regression test | new `tests/test_cli.sh` assertions (truncated, inflated) + existing `tests/fuzz/fuzz_b33offline.cpp` | PASS, plain and ASan/UBSan |
| Consumer never signs with a truncated or inflated batch | reference consumer on the four malformed files | day signers all null, no crash, no wrong signature |

Reproduction: build the reference libi2pd (`git -C i2pd fetch --depth 1 <fork> b33-offline-keys`),
`make -C i2pd libi2pd.a`, then `make b33offlinekeys keyinfo` in i2pd-tools; a shared
master key file is enough to compare both generators.

## 13. Command-by-command parity against upstream i2pd-tools (2026-09-21)

The released v2.1 binary and the current worktree were compared with upstream
PurpleI2P/i2pd-tools master `39f45c6`, built twice: its own pinned libi2pd
`80080fd` for the 13 tools that do not need the b33 API, and
`freeacetone/i2pd` `b33-offline-keys` `fad677b` for `keyinfo` and
`b33offlinekeys`. Every subcommand ran under both implementations with the
same arguments: read-only commands had to print byte-identical output and
exit codes, deterministic writers had to write identical bytes, random writers
were compared by shape and by reading each other's output.

| Requirement / changed output | Check | Observed result |
|---|---|---|
| The released v2.1 artifact passes the project's own suite | `tests/test_cli.sh <release tarball binary>` | PASS (all 15 groups) |
| Readers agree on shared files | `keyinfo` (bare, `-v`, `-d`, `-p`, `-b`) on 10 keys including both tools' `offlinekeys` and `b33offlinekeys` output; `routerinfo` (bare, `-6`, `-f`, `-p`, `-y`) on 3 router.info files | identical except the two documented diagnostics differences below |
| Deterministic writers are byte-identical | `regaddr`, `regaddr_3ld` step1-3, `regaddralias`, `i2pbase64` (both directions), `b33address` | PASS |
| Cross-implementation chains | i2pbox record verified by upstream `verifyhost` and vice versa; upstream `famtool -V` verifies an i2pbox-signed router.info; each side's `keygen`/`offlinekeys`/`b33offlinekeys` output read by the other | PASS |
| Random writers match in shape | `keygen` types 7/11/1/4/0 same report and size, `x25519` same output shape, `offlinekeys` 7/11 same size, `b33offlinekeys` identical structure | PASS |
| Overall verdict | 121 comparisons | 97 identical, 24 differing, all classified below |
| `keyinfo -p` must keep a b33 batch | upstream `-p` decodes to the whole 1518-byte batch file; i2pbox v2.1 printed only the 813 online bytes | **fixed**; now byte-identical (2025-byte base64, round trip reproduces the file) and covered by a new suite assertion |
| `keyinfo -p` on a corrupt batch | truncate the last day, inflate the day count, random tail, wrong ident hash | batch absent from both, differs on corrupt tails: i2pbox drops what does not parse (1085 b64 bytes), upstream re-emits the raw bytes it stored (1849/2025/1665). Wrong ident hash: identical (batch dropped by both). Keeping the strict behaviour is deliberate: the router-side consumer rejects a truncated batch wholesale |
| Help surface | `-h`/`--help` on all 15 subcommands | 13 differ: i2pbox prints `Usage: i2pbox <cmd> ...` everywhere, upstream has no help flag for keygen (writes a file named `-h`/`--help`), regaddr, regaddr_3ld, routerinfo, b33address, verifyhost or autoconf_i2pd, and prints its own usage with the binary path where it does |
| Diagnostics stream and exit status | `keyinfo -b` on an ECDSA key, `keyinfo -v` on a router.info | differ by design: i2pbox writes to stderr and exits 1, upstream writes to stdout and exits 0 |
| keygen RSA types | `keygen 4/5/6` on both sides | upstream writes a **DSA-SHA1** identity while reporting `RSA-2048/3072/4096` (both `keyinfo` implementations read it as DSA-SHA1); i2pbox warns and generates EdDSA (documented fallback) |
| Upstream robustness | upstream `famtool -s` on a valid router.info, upstream `autoconf_i2pd` with stdin at EOF | upstream `famtool -s` segfaults with both libi2pd builds (`RouterInfo::Update` -> `IdentityEx::GetSignatureLen`, null verifier in the unpinned libi2pd); upstream `autoconf_i2pd` prints ~299k lines and then segfaults. i2pbox signs and verifies the same files, and exits 1 on EOF |
| Stricter parsing | `routerinfo` on `tests/vectors/ed25519.info` (a saved `keyinfo -v` text dump) and on random bytes | i2pbox rejects both; upstream's older pin prints a router hash computed from garbage. The fixture was also unused, and is now wired in as a golden `keyinfo -v` vector |
| README accuracy | keygen RSA type numbers | corrected to `4`/`5`/`6` (was `6`/`8`/`12`; `8` is EdDSA-SHA512-ED25519ph) |
| Adversarial batch handling | truncate last day, inflate the day count, random tail, wrong ident hash | i2pbox rejects cleanly and ASan-clean; upstream `keyinfo` reads out of bounds (see section 12) |

Reproduction: `make` in an upstream i2pd-tools clone (after pointing the
submodule at the b33 branch), then drive both binaries from one script over a
shared fixture set. The harness is throwaway, the assertions above are the
durable part.
