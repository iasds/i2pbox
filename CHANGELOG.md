# Changelog

Notable changes per release. Older releases are described in the
[GitHub releases](https://github.com/iasds/i2pbox/releases).

## Unreleased

- The i2pd-side b33 offline-key reader and LeaseSet consumer have landed on
  i2pd master after the 2.61.0 release. `b33offlinekeys` output was
  cross-checked against that implementation (Ed25519 5 d, RedDSA 1 d, Ed25519
  365 d: all days sign and verify, round trips byte-identical); the next i2pd
  release publishes b33 addresses from these files. See
  `docs/VALIDATION-2026-08.md` section 14, which also lists the C++20 bump the
  next submodule upgrade needs.
- Upstream monitor: compare the pinned i2pd submodule by nearest release tag
  (the pin is deliberately one commit past the tag, so the old
  `--exact-match` comparison could never match and left the tracking issue
  open), and track i2pd-tools commits merged past the recorded parity
  baseline.
- Tests: `vain -t 1` regression (i2pd-tools 8b63567 fixed the same class of
  bug in its own allocation loop; i2pbox never had it).

## v2.1.1 — 2026-09-21

Cross-checked against upstream i2pd-tools command by command; one behavioural
gap fixed and one documentation error found. 15 subcommands, no format
changes.

### Fixed

- **`keyinfo -p` keeps a b33 offline-keys batch**: the output serializes the
  online keys together with the batch, matching upstream's libi2pd, so a `-p`
  round trip reproduces a batch file instead of silently dropping the per-day
  keys (v2.1 printed the 813 online bytes of a 1518-byte file). A batch that
  does not parse is still dropped rather than re-emitted verbatim, which keeps
  the reader bounds-checked.
- README: keygen's RSA signature types are `4`/`5`/`6`
  (RSA-2048/3072/4096), not `6`/`8`/`12` (`8` is EdDSA-SHA512-ED25519ph).

### Tests and docs

- suite: a `keyinfo -p` batch round trip, and `tests/vectors/ed25519.info`
  (the golden `keyinfo -v` output, previously unreferenced) is now asserted.
- `docs/VALIDATION-2026-08.md` section 13: the command-by-command parity run
  against i2pd-tools master, 97 of 121 comparisons identical with the rest
  classified. It also records upstream writing DSA-SHA1 identities for
  `keygen 4/5/6` while reporting RSA, upstream `famtool -s` segfaulting, and
  upstream `autoconf_i2pd` looping until it crashes on stdin EOF.
- README: the per-command differences against upstream are an explicit list
  instead of one paragraph.

## v2.1 — 2026-09-21

15 subcommands. New `b33offlinekeys`, a fix to the b33 day handling, and
harder tests around both.

### New: `b33offlinekeys` — encrypted LeaseSets from an offline key

Lets a router publish an encrypted LeaseSet (a `b33` address) without holding
the destination's signing key.

Signing the outer layer of an encrypted LeaseSet needs a key blinded from the
destination's signing key for each day, which `offlinekeys` cannot produce.
`b33offlinekeys` derives that material offline, once per day of the batch, and
appends it to a normal offline-signed key file. The router gets a file it can
publish with for the whole batch, and the destination's signing key never
leaves the offline machine.

```bash
i2pbox b33offlinekeys b33batch.dat router.keys 365
#   router:  keys = b33batch.dat
#            i2cp.leaseSetType = 5
i2pbox keyinfo -b b33batch.dat        # batch span: days, first and last date
```

- batch layout is byte-identical to upstream i2pd-tools `b33offlinekeys`
  (PR #124), so files interoperate once i2pd can read them (the libi2pd side
  still lives on the `b33-offline-keys` branch, not in i2pd master)
- destinations must be Ed25519 or RedDSA; output files are 0600; the
  destination's signing key is not written to the file
- cross-validated against upstream i2pd-tools master and the reference
  libi2pd: identical file structure, both readers agree, and every day of the
  batch was used to sign and verified end to end
  (docs/VALIDATION-2026-08.md, section 12)

### Fixed

- **`b33offlinekeys` day cap**: counts past the 32-bit expiry horizon
  (28,992 days on 2026-09-21, shrinking daily) are rejected up front. They used
  to wrap the per-day expiries into the past and write a file no reader would
  load, while still reporting success. Upstream accepts up to 65,535.
- **`keyinfo -b` batch reader is bounds-checked**: a truncated or inflated
  batch is ignored instead of being walked past the end of the buffer.
  Upstream's reader reads out of bounds on those inputs (ASan
  heap-buffer-overflow, and a bogus span printed by the normal build).
- `keyinfo -b` no longer claims a span for malformed tails, and the
  `b33offlinekeys` help row is aligned with its neighbours.

### Tests and docs

- new libFuzzer target `fuzz_b33offline` mirroring the `keyinfo -b` path, with
  a long-lived seed (2000 days, valid to 2032) that the CLI suite keeps fresh
- CLI suite: batch generation, spans, day-count and input rejections, the
  expiry horizon, adversarial truncated/inflated batches, and a guard that
  fails once the committed fuzz seed has less than 90 days of validity left
- `make interop`: the go-i2p harness now verifies offline signatures and uses
  the correct signing-private-key sizes (DSA 20, P384 48, P521 66, RedDSA 11),
  and the offline keys case is actually exercised
- validation records for all of the above in `docs/VALIDATION-2026-08.md`
  (sections 10-12)
