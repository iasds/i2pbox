# I2P implementation interoperability

i2pbox is an I2P **data-format toolkit**, not a router: it creates and
inspects the standard I2P data structures (keys, destinations, addresses,
records) that every router implementation must speak. Only `autoconf_i2pd`
is i2pd-specific (it generates an `i2pd.conf`). Everything else operates on
I2P network standards and is expected to interoperate with any I2P
implementation.

## Router implementations covered

| Implementation | Language | Role |
|---|---|---|
| [i2pd](https://github.com/PurpleI2P/i2pd) | C++ | bundled as a submodule; i2pbox is built on its `libi2pd` |
| [i2p-java](https://github.com/i2p/i2p.i2p) | Java | the reference implementation (I2P Project) |
| [go-i2p](https://github.com/go-i2p/go-i2p) | Go | independent implementation |
| [emissary](https://github.com/eepnet/emissary) | Rust | independent implementation (protocol stack) |

## Per-command compatibility

`✅` verified by `tests/interop/run_interop.sh`; `⬜` supported by the
implementation but not exercised here; `—` not applicable / not supported.

| i2pbox command | i2pd | i2p-java | go-i2p | emissary |
|---|---|---|---|---|
| `keygen` (EdDSA identity) | ✅ | ⬜ | ✅ destination/b32/hash | ⬜ X25519-only identities |
| `keyinfo` | ✅ | ⬜ | ✅ destination/b32/hash | ⬜ |
| `i2pbase64` | ✅ | ✅ | ✅ | ⬜ |
| `b33address` | ✅ | ⬜ | ⬜ | ⬜ |
| `routerinfo` | ✅ | ⬜ | ✅ parse+verify | ⬜ X25519-only identities |
| `regaddr` / `verifyhost` | ✅ | ⬜ | ⬜ | ⬜ |
| `regaddr_3ld` / `regaddralias` | ✅ | ⬜ | ⬜ | ⬜ |
| `offlinekeys` | ✅ | ⬜ | ⬜ (format differs) | ⬜ |
| `famtool` (X.509 family certs) | ✅ | ⬜ | ⬜ | ⬜ |
| `x25519` (encrypted LeaseSet) | ✅ | ⬜ | ⬜ | ⬜ |
| `vain` | ✅ | ⬜ | ⬜ | ⬜ |
| `autoconf_i2pd` | ✅ | — | — | — |

### Interop verification matrix (run_interop.sh)

| Check | go-i2p | i2p-java | emissary |
|---|---|---|---|
| I2P base64 encode (fixed vector) | ✅ | ✅ | — |
| I2P base64 decode (fixed vector) | ✅ | ✅ | — |
| Destination parse → sha256 → b32/hash | ✅ | ✅ | — |
| router.info parse + signature verify | ✅ | — | ⬜ SKIP (ElGamal identity) |

## Private-key file formats differ per implementation

Router identity keys are **not** a single cross-implementation file format.
The signing key material itself is standard (Ed25519), but the file
wrappers differ:

| Implementation | File format | Reads i2pd `router.keys`? |
|---|---|---|
| i2pd | binary PrivateKeys buffer | yes (native) |
| i2p-java | text properties (`signingPrivateKey=...`) | needs conversion |
| go-i2p | raw Ed25519 bytes (32/64) + separate X25519 key | no — import the standard private key bytes |
| emissary | no private-key file loader (parses public identities only) | no |

Practical import path from i2pbox:

1. `i2pbox keygen router.keys 7` generates an EdDSA-SHA512 router identity.
2. `i2pbox keyinfo -p router.keys` prints the standard private key
   (destination + private bytes, I2P base64).
3. go-i2p: feed the Ed25519 private bytes to its keystore
   (`loadExistingKey` accepts 32/64-byte Ed25519 keys).
4. i2p-java: convert with its `router.keys` tooling (text format).
5. The **network data** derived from the key (destination, b32, hash) is
   byte-identical across implementations — verified by `run_interop.sh`.

## Known capability limits (as of 2026-08)

- **emissary** only parses **X25519-encrypted** identities
  (`InvalidPublicKey(0)` on ElGamal). i2pbox/i2pd generate ElGamal by
  default, so emissary interop on default keys is SKIPped, not failing.
- **go-i2p offline keys**: `ReadOfflineSignature` expects the offline
  signature block, not the i2pd PrivateKeys buffer that `offlinekeys`
  writes; both carry the same I2P Offline Signature standard but in
  different containers.

## Running the verification

```bash
make test               # i2pd regression suite (bundled)
./tests/interop/run_interop.sh ./i2pbox   # go + rust + java cross-validation
```

CI runs the interop matrix on every push (see `.github/workflows/ci.yml`,
`interop` job); i2p-java runs with `continue-on-error` because its build is
heavy.
