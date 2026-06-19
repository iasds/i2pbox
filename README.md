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
| `vain` | Generate vanity .b32.i2p address |
| `keygen` | Generate random I2P keys |
| `keyinfo` | Display info about a private key |
| `famtool` | Router family: generate, sign, or verify |
| `routerinfo` | Display router info (hosts, ports, firewall rules) |
| `regaddr` | Register an I2P address |
| `regaddr_3ld` | Register a 3LD address (3-step process) |
| `i2pbase64` | Encode/decode I2P Base64 |
| `offlinekeys` | Generate offline signing keys |
| `b33address` | Convert Base64 destination to b33 address |
| `regaddralias` | Register an address alias |
| `x25519` | Generate X25519 key pair for encrypted LeaseSet |
| `verifyhost` | Verify host record signature |
| `autoconf_i2pd` | Interactive i2pd.conf generator |

Usage: `i2pbox <command> [args...]` — each command accepts the same arguments as the original standalone tool.

### Examples

```bash
# Generate keys
i2pbox keygen router.keys

# Inspect a key
i2pbox keyinfo -v router.keys

# Vanity address mining (4 threads, regex mode)
i2pbox vain '^i2p' -r -t 4

# Router family sign + verify
i2pbox famtool -g -n myfamily -c myfamily.crt -k myfamily.key
i2pbox famtool -s -n myfamily -k myfamily.key -i router.keys -f router.info
i2pbox famtool -V -n myfamily -c myfamily.crt -f router.info

# Register an address
i2pbox regaddr router.keys myname.i2p

# Generate X25519 keys for encrypted LeaseSet
i2pbox x25519

# Interactive i2pd.conf wizard
i2pbox autoconf_i2pd
```

## Build

### Dependencies

- g++ or clang (C++17)
- OpenSSL (libssl-dev / openssl@3)
- Boost (libboost-program-options-dev / boost)
- zlib (zlib1g-dev / zlib)

### Compile

```bash
make -j$(nproc)
```

This builds `libi2pd.a` from the i2pd submodule (~2 minutes first build), then links everything into a single `i2pbox` binary.

### Install

```bash
sudo make install   # → /usr/local/bin/i2pbox
```

The binary has no runtime dependencies beyond standard system libraries.

## Comparison with i2pd-tools

| | i2pd-tools | i2pbox |
|---|---|---|
| **Binaries** | 14 separate | 1 |
| **Compile** | 14 linker invocations | 1 |
| **Stripped size** | ~70 MB (14 × ~5 MB) | ~5.2 MB |
| **Usage** | `./toolname args` | `i2pbox toolname args` |
| **Output** | — | identical |

## FAQ

### Why a single binary?

Less clutter, simpler distribution, and reduced disk usage (shared i2pd library linked once).

### Are there any behavioral differences?

No. Each subcommand is functionally identical to the original. The code changes are mechanical: `main()` → `tool_xxx()`, `InitCrypto()` centralized in `main.cpp`.

### Shell aliases for original names?

```bash
alias keygen='i2pbox keygen'
alias keyinfo='i2pbox keyinfo'
alias vain='i2pbox vain'
# ... etc
```
