# i2pbox

**All [i2pd-tools](https://github.com/PurpleI2P/i2pd-tools) in a single binary.**

The original i2pd-tools builds **14 separate binaries**. i2pbox merges them into one:

```
Before: 14 binaries, 14 compilations
After:  1 binary, 1 make, 14 subcommands
```

## Quick Start

### Download binary (Linux x86_64)

```bash
curl -LO https://github.com/iasds/i2pbox/releases/download/v1.0.0/i2pbox-linux-x86_64.tar.gz
tar xzf i2pbox-linux-x86_64.tar.gz
sudo cp i2pbox /usr/local/bin/
i2pbox help
```

### Build from source

```bash
git clone --recurse-submodules https://github.com/iasds/i2pbox.git
cd i2pbox

# Debian/Ubuntu
sudo apt install build-essential libssl-dev libboost-program-options-dev zlib1g-dev

# macOS
brew install openssl@3 boost zlib

make -j$(nproc)
sudo make install
```

---

## Command Reference

### `keygen` — Generate I2P Keys

Create a new random key pair. The output file is a binary blob containing the full private key.

```
i2pbox keygen <output-file> [signature-type]
```

**Options:**

| Argument | Default | Description |
|----------|---------|-------------|
| `output-file` | *(required)* | Path to save the key file |
| `signature-type` | `ED25519-SHA512` (7) | Signature algorithm: `7`, `0` (DSA), `1` (ECDSA-P256), `3` (ECDSA-P521), `6` (RSA-4096), `11` (RedDSA) |

**Example:**

```bash
# Generate default Ed25519 keys
i2pbox keygen router.keys

# Generate RedDSA keys (for encrypted LeaseSet)
i2pbox keygen server.keys 11
```

Output shows your `.b32.i2p` address and the signature type used.

---

### `keyinfo` — Inspect Private Keys

Display information about a key file — address, signature type, encryption type, expiry.

```
i2pbox keyinfo [-v] [-d] [-p] [-b] <keyfile>
```

**Options:**

| Flag | Description |
|------|-------------|
| *(none)* | Print the `.b32.i2p` address |
| `-v` | Verbose: full details including signature type, encryption type, offline status |
| `-d` | Print the Base64 destination (public key) |
| `-p` | Print the Base64 private key |
| `-b` | Print the blinded b33 address (for encrypted LeaseSet) |

**Example:**

```bash
# See your address
i2pbox keyinfo router.keys
# Output: abcdef...xyz.b32.i2p

# Full details
i2pbox keyinfo -v router.keys
# Output:
#   Destination: AaBbCc... (base64)
#   Destination Hash: XxYyZz...
#   B32 Address: abcdef....b32.i2p
#   Signature Type: ED25519-SHA512
#   Encryption Type: 0
```

---

### `vain` — Vanity Address Generator

Mine for a `.b32.i2p` address matching a pattern. Uses all CPU cores by default.

```
i2pbox vain <pattern> [-r] [-t threads] [-o output] [-m]
```

**Options:**

| Flag | Description |
|------|-------------|
| `pattern` | Text prefix or regex pattern to match |
| `-r` | Treat pattern as regex instead of plain text |
| `-t N` | Number of threads (default: all cores) |
| `-o path` | Output file path (default: `<address>.dat` ) |
| `-m` | Multi-mode: keep searching for multiple matches |

**Example:**

```bash
# Find an address starting with "i2p"
i2pbox vain i2p -t 4

# Regex: address starting with a letter then "2p"
i2pbox vain '^[a-z]2p' -r -t 8

# Keep finding until you stop it (Ctrl+C)
i2pbox vain i2p -t 4 -m
```

The longer the pattern, the longer it takes (exponentially). A 3-character prefix takes seconds; 6+ characters can take hours.

---

### `famtool` — Router Family Management

Create and manage I2P router families. A family is a group of routers that share a cryptographic identity for trust purposes.

```
i2pbox famtool -g -n <family-name> -c <cert-file> -k <key-file>
i2pbox famtool -s -n <family-name> -k <key-file> -i <router.keys> -f <router.info>
i2pbox famtool -V -n <family-name> -c <cert-file> -f <router.info>
```

**Options:**

| Flag | Description |
|------|-------------|
| `-g` | Generate a new family signing key and certificate |
| `-s` | Sign a router.info with the family key |
| `-V` | Verify a signed router.info against the family certificate |
| `-n name` | Family name (e.g. `myfamily`) |
| `-c file` | Certificate file (`.crt`) |
| `-k file` | Private key file (`.pem`) |
| `-i file` | Router keys file (input) |
| `-f file` | Router info file |
| `-v` | Verbose output |

**Example — full workflow:**

```bash
# Step 1: Generate a family identity
i2pbox famtool -g -n myfamily -c myfamily.crt -k myfamily.key

# Step 2: Sign a router into the family
i2pbox famtool -s -n myfamily -k myfamily.key -i router.keys -f router.info

# Step 3: Verify the signature
i2pbox famtool -V -n myfamily -c myfamily.crt -f router.info
```

---

### `routerinfo` — Inspect Router Info Files

Parse a `router.info` file and display published addresses, ports, and transport protocols. Can also generate iptables rules.

```
i2pbox routerinfo [-6] [-f] [-p] [-y] <router.info> [more files...]
```

**Options:**

| Flag | Description |
|------|-------------|
| *(none)* | Print router hash + IPv4 addresses |
| `-6` | Include IPv6 addresses |
| `-f` | Generate iptables ACCEPT rules (firewall format) |
| `-p` | Include port numbers in output |
| `-y` | Include Yggdrasil addresses |

**Example:**

```bash
# See addresses published by a router
i2pbox routerinfo /var/lib/i2pd/router.info
# Output:
#   Router Hash: AbCdEf...
#   NTCP2: 1.2.3.4
#   SSU2: 1.2.3.4

# Generate iptables rules for all routers in a directory
i2pbox routerinfo -f /var/lib/i2pd/netDb/r*.dat
# Output:
#   # AbCdEf...
#   -A OUTPUT -p tcp -d 1.2.3.4 --dport 12345 -j ACCEPT
```

---

### `regaddr` — Register an I2P Address

Generate a signed registration string for an I2P address (used with registrars like `reg.i2p`).

```
i2pbox regaddr <keyfile> <address>
```

**Example:**

```bash
# Register "myname.i2p" for your router
i2pbox regaddr router.keys myname.i2p
# Output: myname.i2p=<base64-dest>#!sig=<base64-signature>
```

Paste the output into the registration form at your I2P registrar.

---

### `regaddr_3ld` — Register a Third-Level Domain

Three-step process for registering a subdomain (e.g. `myservice.mydomain.i2p`).

```
i2pbox regaddr_3ld step1 <privkey> <address>
i2pbox regaddr_3ld step2 <step1-output> <old-privkey> <old-address>
i2pbox regaddr_3ld step3 <step2-output> <privkey>
```

**Example — registering `blog.myname.i2p`:**

```bash
# Step 1: Generate the subdomain registration request
i2pbox regaddr_3ld step1 router.keys blog.myname.i2p > step1.txt

# Step 2: Sign with the parent domain's key
i2pbox regaddr_3ld step2 step1.txt parent.keys myname.i2p > step2.txt

# Step 3: Finalize with the subdomain key
i2pbox regaddr_3ld step3 step2.txt router.keys > registration.txt
```

Submit `registration.txt` to the address registrar.

---

### `regaddralias` — Register an Address Alias

Link a new key to an existing address (for key rotation).

```
i2pbox regaddralias <old-keyfile> <new-keyfile> <address>
```

**Example:**

```bash
# Rotate to new keys for the same address
i2pbox keygen new-router.keys
i2pbox regaddralias old-router.keys new-router.keys myname.i2p
```

---

### `i2pbase64` — Base64 Encode / Decode

I2P uses a custom Base64 alphabet (different from standard Base64). This tool handles I2P-format Base64.

```
i2pbox i2pbase64 [-d] [file]
```

**Options:**

| Flag | Description |
|------|-------------|
| *(none)* | Encode stdin/file to Base64 |
| `-d` | Decode Base64 to raw bytes |

**Example:**

```bash
# Encode
echo "hello" | i2pbox i2pbase64
# Output: aGVsbG8K

# Decode
echo "aGVsbG8K" | i2pbox i2pbase64 -d
# Output: hello

# Encode a binary file
i2pbox i2pbase64 some-binary-file.dat
```

---

### `offlinekeys` — Generate Offline Signing Keys

Create time-limited offline signing keys. Used so a router can publish LeaseSets without having the master private key online.

```
i2pbox offlinekeys <output> <master-keyfile> [sig-type] [days]
```

**Options:**

| Argument | Default | Description |
|----------|---------|-------------|
| `output` | *(required)* | Output file for offline keys |
| `master-keyfile` | *(required)* | Your master private key file |
| `sig-type` | `7` (Ed25519) | Transient signature type |
| `days` | `365` | Validity period in days |

**Example:**

```bash
# Generate offline keys valid for 90 days
i2pbox offlinekeys offline.dat router.keys 7 90
```

---

### `b33address` — Convert to Blinded b33 Address

Compute the blinded b33 address for encrypted LeaseSet (LS2). Reads Base64 destination from stdin.

```
i2pbox b33address
```

**Example:**

```bash
# Get the destination Base64 and pipe to b33address
i2pbox keyinfo -d router.keys | i2pbox b33address
# Output:
#   b33 address: abcdef....b32.i2p
#   Today's store hash: XxYyZz...
```

---

### `x25519` — Generate X25519 Key Pair

Generate an X25519 key pair for authenticating with encrypted LeaseSets (LS2, LeaseSet Type 5).

```
i2pbox x25519
```

**Example:**

```bash
i2pbox x25519
# Output:
#   PublicKey: KB0fGMGzCMzHur89...
#   PrivateKey: iGXVPyaik9mv~51T...
```

**To use in i2pd.conf:**

Server side (`i2pd.conf`):
```
i2cp.leaseSetType = 5
i2cp.leaseSetAuthType = 1
i2cp.leaseSetClient.dh.210 = client-name:PublicKey
```

Client side (`tunnels.conf`):
```
i2cp.leaseSetPrivKey = PrivateKey
```

---

### `verifyhost` — Verify Host Record Signature

Verify the cryptographic signature on a host registration record (from `regaddr` or a registrar).

```
i2pbox verifyhost '<host-record>'
```

**Example:**

```bash
# Generate a record
RECORD=$(i2pbox regaddr router.keys myname.i2p)

# Verify it
i2pbox verifyhost "$RECORD"
# Output: (if valid — silent success, exit 0)
#         Invalid destination signature. (if bad)
```

---

### `autoconf_i2pd` — Interactive Config Generator

Interactive CLI wizard that walks you through i2pd configuration and generates an `i2pd.conf` file.

```
i2pbox autoconf_i2pd
```

Supports English and Russian. Prompts for: network type (clearnet/Yggdrasil), IPv4/IPv6, bandwidth, port numbers, floodfill mode, transit settings, HTTP console language, and more.

---

## Build from Source

### Prerequisites

| Package | Debian/Ubuntu | macOS (Homebrew) | Fedora |
|---------|---------------|------------------|--------|
| C++ compiler | `build-essential` | Xcode CLI tools | `gcc-c++` |
| OpenSSL | `libssl-dev` | `openssl@3` | `openssl-devel` |
| Boost | `libboost-program-options-dev` | `boost` | `boost-devel` |
| zlib | `zlib1g-dev` | `zlib` | `zlib-devel` |

### Build

```bash
git clone --recurse-submodules https://github.com/iasds/i2pbox.git
cd i2pbox
make -j$(nproc)
```

This builds `libi2pd.a` from the i2pd submodule (~2 minutes on first build), then links everything into a single `i2pbox` binary.

### Install

```bash
sudo make install          # → /usr/local/bin/i2pbox
# or just copy it:
sudo cp i2pbox /usr/local/bin/
```

The binary is self-contained — no runtime dependencies beyond standard system libraries (`libssl`, `libcrypto`, `libboost_program_options`, `libz`, `libpthread`).

---

## Comparison with i2pd-tools

| | i2pd-tools | i2pbox |
|---|---|---|
| **Binaries** | 14 separate | 1 |
| **Compile** | 14 linker invocations | 1 |
| **Unstripped size** | ~750 MB (14 × ~53 MB) | ~58 MB |
| **Stripped size** | ~70 MB (14 × ~5 MB) | ~5.2 MB |
| **Usage** | `./toolname args` | `i2pbox toolname args` |
| **Code changes** | Original | `main()` → `tool_xxx()`, crypto init centralized |
| **Output** | identical | identical |

All 14 tools passed **26 side-by-side comparison tests** against the original — same output, same exit codes, same behavior.

---

## FAQ

### Why a single binary?

- **Less clutter**: one file instead of 14
- **Simpler distribution**: one download, one install
- **Easier discovery**: `i2pbox help` lists everything
- **Reduced disk usage**: shared i2pd library linked once

### Are there any behavioral differences?

No. Each subcommand is functionally identical to the original standalone tool. The code changes are mechanical: `main()` renamed to `tool_xxx()`, `InitCrypto()`/`TerminateCrypto()` moved to a single centralized call.

### Can I still use the original tool names?

Create shell aliases if you prefer:
```bash
alias keygen='i2pbox keygen'
alias keyinfo='i2pbox keyinfo'
alias vain='i2pbox vain'
# ... etc
```

---

## License

BSD 3-Clause — same as the original [i2pd-tools](https://github.com/PurpleI2P/i2pd-tools).

## Acknowledgments

This project repackages [PurpleI2P/i2pd-tools](https://github.com/PurpleI2P/i2pd-tools). All tool logic and cryptographic code is the work of the i2pd contributors. i2pbox only provides the unified dispatch layer.
