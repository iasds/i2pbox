# i2pbox

**All [i2pd-tools](https://github.com/PurpleI2P/i2pd-tools) in a single binary.**

The original i2pd-tools builds **14 separate binaries**. i2pbox merges them into one:

```
Before: 14 binaries, 14 compilations
After:  1 binary, 1 make, 14 subcommands
```

## I2P ecosystem positioning

i2pbox is an I2P **data-format toolkit**: it creates and inspects the
standard I2P data structures (keys, destinations, addresses, records) that
every router implementation speaks. Only `autoconf_i2pd` is i2pd-specific
(it generates an `i2pd.conf`); the other 13 commands interoperate with any
I2P implementation — i2pd (C++), i2p-java (Java), go-i2p (Go) and emissary
(Rust). CI cross-validates keygen/i2pbase64/keyinfo/routerinfo outputs
against those implementations (`make interop` locally, `interop` job in CI).
See [docs/INTEROP.md](docs/INTEROP.md) for the compatibility matrix and the
per-implementation private-key file formats.

## Quick Start

```bash
git clone --recurse-submodules https://github.com/iasds/i2pbox.git
cd i2pbox

# Debian/Ubuntu
sudo apt install build-essential libssl-dev libboost-program-options-dev zlib1g-dev

# macOS
brew install openssl@3 boost zlib

make -j$(nproc)
sudo make install

i2pbox help
```

## Commands

| Command | Description |
|---|---|
| `keygen` | Generate random I2P keys |
| `keyinfo` | Display info about a private key |
| `vain` | Generate vanity .b32.i2p address |
| `famtool` | Router family: generate, sign, or verify |
| `routerinfo` | Display router info (hosts, ports, firewall rules) |
| `regaddr` | Register an I2P address |
| `regaddr_3ld` | Register a 3LD address (3-step process) |
| `regaddralias` | Register an address alias |
| `i2pbase64` | Encode/decode I2P Base64 |
| `offlinekeys` | Generate offline signing keys |
| `b33address` | Convert Base64 destination to b33 address |
| `x25519` | Generate X25519 key pair for encrypted LeaseSet |
| `verifyhost` | Verify host record signature |
| `autoconf_i2pd` | Interactive i2pd.conf generator |

## Usage

### keygen

```
i2pbox keygen <output-file> [signature-type]
```

| Arg | Default | Description |
|---|---|---|
| `output-file` | *(required)* | Path to save the key file |
| `signature-type` | `7` (EdDSA) | `0`=DSA, `1`=ECDSA-P256, `3`=ECDSA-P521, `7`=EdDSA, `11`=RedDSA |

RSA types (`6`=RSA-2048, `8`=RSA-3072, `12`=RSA-4096) are rejected with a warning and fall back to EdDSA.

```bash
i2pbox keygen router.keys           # EdDSA (default)
i2pbox keygen server.keys 11        # RedDSA (for encrypted LeaseSet)
```

### keyinfo

```
i2pbox keyinfo [-v] [-d] [-p] [-b] <keyfile>
```

| Flag | Output |
|---|---|
| *(none)* | `.b32.i2p` address |
| `-v` | Full details: destination, hash, b32, signature type, encryption type, offline status |
| `-d` | Base64 destination (public key) |
| `-p` | Base64 private key |
| `-b` | Blinded b33 address (for encrypted LeaseSet) |

```bash
i2pbox keyinfo router.keys          # → abcdef....b32.i2p
i2pbox keyinfo -v router.keys       # verbose
i2pbox keyinfo -d router.keys | i2pbox b33address   # pipe to b33
```

### vain

```
i2pbox vain <pattern> [-r] [-t threads] [-o output] [-m] [-s sig-type]
```

| Flag | Description |
|---|---|
| `pattern` | Text prefix or regex pattern |
| `-r` | Treat pattern as regex |
| `-t N` | Threads (default: all cores) |
| `-o path` | Output file (default: `<address>.dat`) |
| `-m` | Multi-mode: keep finding after first match |
| `-s type` | Signature type (default: 7) |

```bash
i2pbox vain i2p -t 4               # prefix match, 4 threads
i2pbox vain '^[a-z]2p' -r -t 8     # regex match
i2pbox vain i2p -t 4 -m            # multi-mode (Ctrl+C to stop)
```

### famtool

```
i2pbox famtool -g -n <name> -c <cert> -k <key>
i2pbox famtool -s -n <name> -k <key> -i <router.keys> -f <router.info>
i2pbox famtool -V -n <name> -c <cert> -f <router.info>
```

| Flag | Description |
|---|---|
| `-g` | Generate a new family signing key and certificate |
| `-s` | Sign a router.info with the family key |
| `-V` | Verify a signed router.info |
| `-n name` | Family name |
| `-c file` | Certificate file (.crt) |
| `-k file` | Private key file (.key) |
| `-i file` | Router keys (for signing) |
| `-f file` | Router info file |
| `-P password` | Encrypt (with `-g`) or decrypt (with `-s`) the private key (AES-256-CBC). Without it the legacy unencrypted PEM format is used. Note: the password is visible in the process list. |
| `-e days` | Certificate validity in days (with `-g`), default 3650 = 10 years |
| `-v` | Verbose |

```bash
i2pbox famtool -g -n myfam -c myfam.crt -k myfam.key
i2pbox famtool -g -n myfam -c myfam.crt -k myfam.key -P secret -e 3650   # encrypted key
i2pbox famtool -s -n myfam -k myfam.key -i router.keys -f router.info
i2pbox famtool -s -n myfam -k myfam.key -P secret -i router.keys -f router.info   # encrypted key
i2pbox famtool -V -n myfam -c myfam.crt -f router.info
```

### routerinfo

```
i2pbox routerinfo [-6] [-f] [-p] [-y] <router.info> [...]
```

| Flag | Description |
|---|---|
| *(none)* | Router hash + IPv4 addresses |
| `-6` | Include IPv6 addresses |
| `-f` | Generate iptables ACCEPT rules |
| `-p` | Include port numbers |
| `-y` | Include Yggdrasil addresses |

```bash
i2pbox routerinfo /var/lib/i2pd/router.info
i2pbox routerinfo -fp /var/lib/i2pd/netDb/r*.dat   # firewall rules
```

### regaddr

```
i2pbox regaddr <keyfile> <address>
```

Generates a signed registration string. Submit the output to an I2P registrar.

```bash
i2pbox regaddr router.keys myname.i2p
# → myname.i2p=<base64>#!sig=<signature>
```

### regaddr_3ld

```
i2pbox regaddr_3ld step1 <privkey> <address>
i2pbox regaddr_3ld step2 <step1-file> <parent-key> <parent-address>
i2pbox regaddr_3ld step3 <step2-file> <privkey>
```

Three-step process for subdomain registration (e.g. `blog.mydomain.i2p`).

```bash
i2pbox regaddr_3ld step1 router.keys blog.myname.i2p > step1.txt
i2pbox regaddr_3ld step2 step1.txt parent.keys myname.i2p > step2.txt
i2pbox regaddr_3ld step3 step2.txt router.keys > registration.txt
```

### regaddralias

```
i2pbox regaddralias <old-keyfile> <new-keyfile> <address>
```

Links a new key to an existing address (key rotation).

```bash
i2pbox keygen new-keys.dat
i2pbox regaddralias old-keys.dat new-keys.dat myname.i2p
```

### i2pbase64

```
i2pbox i2pbase64 [-d] [file]
```

| Flag | Description |
|---|---|
| *(none)* | Encode stdin/file to I2P Base64 |
| `-d` | Decode Base64 to raw bytes |

I2P uses a custom Base64 alphabet (`-` and `~` instead of `+` and `/`, with no `=` padding).

```bash
echo "hello" | i2pbox i2pbase64             # encode
echo "aGVsbG8K" | i2pbox i2pbase64 -d       # decode
i2pbox i2pbase64 binary-file.dat            # encode file
```

### offlinekeys

```
i2pbox offlinekeys <output> <master-keyfile> [sig-type] [days]
```

| Arg | Default | Description |
|---|---|---|
| `output` | *(required)* | Output file for offline keys |
| `master-keyfile` | *(required)* | Master private key |
| `sig-type` | `7` (EdDSA) | Transient signature type |
| `days` | `365` | Validity in days |

```bash
i2pbox offlinekeys offline.dat router.keys 7 90   # valid 90 days
```

### b33address

```
i2pbox b33address
```

Reads Base64 destination from stdin, outputs blinded b33 address + today's store hash. Used for encrypted LeaseSet (LS2).

```bash
i2pbox keyinfo -d router.keys | i2pbox b33address
# → b33 address: abcdef....b32.i2p
#   Today's store hash: XxYyZz...
```

### x25519

```
i2pbox x25519
```

Generates an X25519 key pair for encrypted LeaseSet authentication (LeaseSet Type 5).

```bash
i2pbox x25519
# → PublicKey: KB0fGMGzCMz...
#   PrivateKey: iGXVPyaik9m...

# Server i2pd.conf:
#   i2cp.leaseSetType = 5
#   i2cp.leaseSetAuthType = 1
#   i2cp.leaseSetClient.dh.210 = client:PublicKey

# Client tunnels.conf:
#   i2cp.leaseSetPrivKey = PrivateKey
```

### verifyhost

```
i2pbox verifyhost '<host-record>'
```

Verifies the cryptographic signature on a host registration record. Silent on success (exit 0); prints error on failure.

```bash
RECORD=$(i2pbox regaddr router.keys myname.i2p)
i2pbox verifyhost "$RECORD"
```

### autoconf_i2pd

```
i2pbox autoconf_i2pd
```

Interactive wizard that generates an `i2pd.conf`. Supports English and Russian. Prompts for network type, IP version, bandwidth, ports, floodfill mode, transit settings, and more.

```bash
i2pbox autoconf_i2pd
```

## Testing

```bash
make test              # regression suite (tests/test_cli.sh): 14 subcommands, cross-tool chains, golden vectors
make bench             # perf baseline: 100x keygen/keyinfo/i2pbase64 + vain smoke (~2s)
make fuzz-smoke        # local corpus smoke (no clang required)
make fuzz-build && ./tests/fuzz/run_fuzz_smoke.sh 15   # libFuzzer smoke (clang)
make interop           # cross-validate against go-i2p / emissary / i2p-java (needs Go/Rust/JDK)
```

CI runs `test` (normal + ASan/UBSan with leak detection), `fuzz-smoke`, and `interop` on every push — see [.github/workflows/ci.yml](.github/workflows/ci.yml).

### Shell completion

```bash
source contrib/completion/bash/i2pbox   # bash
# zsh: copy contrib/completion/zsh/_i2pbox to $fpath (e.g. /usr/share/zsh/site-functions/)
```

## See also

- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev loop, style, sanitizer flags, test expectations
- [docs/INTEROP.md](docs/INTEROP.md) — per-implementation compatibility matrix

## Build

Dependencies: g++/clang (C++17), OpenSSL, Boost (program_options), zlib.

```bash
git clone --recurse-submodules https://github.com/iasds/i2pbox.git
cd i2pbox
make -j$(nproc)
sudo make install   # → /usr/local/bin/i2pbox
```

First build compiles `libi2pd.a` from the i2pd submodule (~2 minutes).

### Platform support

The Makefile carries branches for Linux, macOS, FreeBSD, and Windows
(MSYS2/clang64), but **only Linux is tested by CI** (regression suite +
ASan/UBSan on Ubuntu 24.04). Other platforms build from the same sources but
are best-effort; please report breakage.

| Platform | Build | CI-tested |
|---|---|---|
| Linux (glibc) | ✅ | ✅ |
| macOS (Homebrew, openssl@3) | ⚠️ best-effort | ❌ |
| FreeBSD | ⚠️ best-effort | ❌ |
| Windows (MSYS2/clang64) | ⚠️ best-effort | ❌ |

## Comparison

| | i2pd-tools | i2pbox |
|---|---|---|
| **Binaries** | 14 separate | 1 |
| **Compile** | 14 link invocations | 1 |
| **Stripped size** | ~70 MB | ~5.2 MB |
| **Usage** | `./toolname args` | `i2pbox toolname args` |
| **Output** | — | same upstream logic, regression-tested (interop chains + golden vectors) |

## FAQ

### Behavioral differences?

None known. Each subcommand is built from the same upstream i2pd-tools logic, so behavior mirrors the originals (the one documented deviation is keygen's RSA fallback, see above). The regression suite (`tests/test_cli.sh`) covers all 14 subcommands with cross-tool interoperability chains (regaddr → verifyhost, keygen → keyinfo, offlinekeys → keyinfo, famtool sign → verify), golden vectors, and format assertions. CI runs it on both a normal build and an ASan/UBSan build with leak detection.

### Alias original names?

```bash
alias keygen='i2pbox keygen'
alias keyinfo='i2pbox keyinfo'
alias vain='i2pbox vain'
# ...
```
