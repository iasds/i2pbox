# i2pbox

**All [i2pd-tools](https://github.com/PurpleI2P/i2pd-tools) in a single binary.**

The original i2pd-tools builds **14 separate binaries**. i2pbox merges them into one:

```
Before: 14 binaries, 14 compilations
After:  1 binary, 1 make, 14 subcommands
```

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
| `-v` | Verbose |

```bash
i2pbox famtool -g -n myfam -c myfam.crt -k myfam.key
i2pbox famtool -s -n myfam -k myfam.key -i router.keys -f router.info
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

I2P uses a custom Base64 alphabet (`.`, `-`, `~` instead of `+`, `/`, `=`).

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

## Build

Dependencies: g++/clang (C++17), OpenSSL, Boost (program_options), zlib.

```bash
git clone --recurse-submodules https://github.com/iasds/i2pbox.git
cd i2pbox
make -j$(nproc)
sudo make install   # → /usr/local/bin/i2pbox
```

First build compiles `libi2pd.a` from the i2pd submodule (~2 minutes).

## Comparison

| | i2pd-tools | i2pbox |
|---|---|---|
| **Binaries** | 14 separate | 1 |
| **Compile** | 14 link invocations | 1 |
| **Stripped size** | ~70 MB | ~5.2 MB |
| **Usage** | `./toolname args` | `i2pbox toolname args` |
| **Output** | — | identical (verified by cross-validation) |

## FAQ

### Behavioral differences?

None. Each subcommand is functionally identical to the original. 24/24 cross-validation tests pass.

### Alias original names?

```bash
alias keygen='i2pbox keygen'
alias keyinfo='i2pbox keyinfo'
alias vain='i2pbox vain'
# ...
```
