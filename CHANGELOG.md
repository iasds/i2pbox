# Changelog

Notable changes per release. Older releases are described in the
[GitHub releases](https://github.com/iasds/i2pbox/releases).

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
