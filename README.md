# i2pbox

**All [i2pd-tools](https://github.com/PurpleI2P/i2pd-tools) in a single binary.**

The original i2pd-tools builds **14 separate binaries** — compile once per tool, manage 14 files, remember 14 names. i2pbox merges them all into one binary with subcommands.

```
Before: vain keygen keyinfo famtool routerinfo regaddr regaddr_3ld i2pbase64 offlinekeys b33address regaddralias x25519 verifyhost autoconf_i2pd
After:  i2pbox <command>
```

One `make`, one binary, zero confusion.

## Quick Start

```bash
# Clone with submodule (i2pd is a dependency)
git clone --recurse-submodules https://github.com/iasds/i2pbox.git
cd i2pbox

# Install build deps (Debian/Ubuntu)
sudo apt install build-essential libssl-dev libboost-program-options-dev zlib1g-dev

# Build
make -j$(nproc)

# Done
./i2pbox help
```

## Usage

```
i2pbox <command> [args...]
```

| Command | Description |
|---------|-------------|
| `keygen` | Generate random I2P keys |
| `keyinfo` | Display private key details |
| `vain` | Generate vanity .b32.i2p address |
| `famtool` | Router family: generate / sign / verify |
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

### Examples

```bash
# Generate router keys
i2pbox keygen my-router.keys

# Inspect them
i2pbox keyinfo -v my-router.keys

# Generate a vanity address (prefix "i2p")
i2pbox vain i2p -t 4

# Generate X25519 keys for encrypted LeaseSet
i2pbox x25519

# Encode/decode Base64
echo "hello i2p" | i2pbox i2pbase64
echo "aGVsbG8gaTJwCg==" | i2pbox i2pbase64 -d

# Register an address
i2pbox regaddr my-router.keys myhost.i2p

# Interactive config generator
i2pbox autoconf_i2pd
```

## Build from Source

### Requirements

- C++17 compiler (GCC 8+, Clang 7+)
- OpenSSL development headers
- Boost (program_options)
- zlib

### Debian / Ubuntu

```bash
sudo apt install build-essential libssl-dev libboost-program-options-dev zlib1g-dev
```

### macOS

```bash
brew install openssl@3 boost zlib
make
```

### Build

```bash
make -j$(nproc)
```

The `i2pd` submodule is built automatically as `libi2pd.a` and linked statically.

### Install

```bash
sudo make install   # → /usr/local/bin/i2pbox
```

Or just copy the binary wherever you want — it has no runtime dependencies beyond standard system libs.

## How It Differs from i2pd-tools

| | i2pd-tools | i2pbox |
|---|---|---|
| Binaries | 14 separate | 1 |
| Compilation | 14 `g++ -o` invocations | 1 |
| Disk usage (unstripped) | ~750 MB (14 × ~53 MB) | ~58 MB |
| Usage | `./toolname args` | `./i2pbox toolname args` |
| Code changes | Original | `main()` → `tool_xxx()`, crypto init centralized |

Functionally identical — same output, same exit codes, same behavior. All 14 tools pass side-by-side comparison tests against the original.

## License

BSD 3-Clause — same as the original [i2pd-tools](https://github.com/PurpleI2P/i2pd-tools).

## Acknowledgments

This project is a repackaging of [PurpleI2P/i2pd-tools](https://github.com/PurpleI2P/i2pd-tools). All credit for the tools themselves goes to the i2pd contributors.
