# Security Audit: i2pbox

## Summary

Comprehensive security vulnerability assessment of the i2pbox project — a C++ binary that merges 14 i2pd-tools (keygen, keyinfo, famtool, regaddr, vain, x25519, verifyhost, etc.) into a single executable. The audit covers memory safety, cryptographic correctness, input validation, and supply-chain risks in both the i2pbox wrapper code and its i2pd static library dependency.

## Motivation

i2pbox handles I2P private keys, generates cryptographic material, signs router info, and processes untrusted user input (filenames, addresses, base64 data, regex patterns). A vulnerability could leak private keys, produce weak crypto material, or allow code execution. Since i2pbox is published as a public binary and intended for privacy-conscious users, security is paramount.

## Scope

### In Scope
- All 14 i2pbox tool source files (`main.cpp`, `keygen.cpp`, `keyinfo.cpp`, `famtool.cpp`, `routerinfo.cpp`, `regaddr.cpp`, `regaddr_3ld.cpp`, `i2pbase64.cpp`, `offlinekeys.cpp`, `b33address.cpp`, `regaddralias.cpp`, `x25519.cpp`, `verifyhost.cpp`, `autoconf_i2pd.cpp`, `vain.cpp`)
- Shared headers (`tools.h`, `common/key.hpp`, `vanity.hpp`)
- Build system (`Makefile`) — compiler flags, link options, hardening
- Static library linkage (`libi2pd.a`) — not deep code review of i2pd itself, but interface-level risks
- Key file handling (read, write, permissions)
- OpenSSL usage patterns

### Out of Scope
- Full source audit of the i2pd submodule (upstream project, separate review)
- Network protocol security (I2P protocol itself)
- Runtime environment security (OS hardening, container escape)
- Denial-of-service against I2P network

## User Scenarios

### Scenario 1: Key Generation Security
A user runs `i2pbox keygen mykey.dat` to generate I2P identity keys. The generated keys must be cryptographically sound — sufficient entropy, correct key type, no bias in randomness. The output file must not be world-readable.

### Scenario 2: Private Key Handling
A user runs `i2pbox keyinfo -p mykey.dat` to display their private key. The tool must not leak the key to stderr, logs, core dumps, or leave it in memory longer than necessary.

### Scenario 3: Untrusted Input Processing
A user provides a maliciously crafted filename, base64 string, or regex pattern to any subcommand. The tool must not crash, execute arbitrary code, or overflow buffers.

### Scenario 4: Vanity Address Generation
A user runs `i2pbox vain <pattern> -t 8` with multiple threads. Thread safety, memory management, and the SHA-256 implementation must be correct — no data races, no use-after-free, no integer overflow in the nonce counter.

### Scenario 5: Certificate/Family Operations
A user generates or verifies family certificates via `famtool`. OpenSSL API usage must be correct — no deprecated API misuse, proper error checking, no memory leaks.

### Scenario 6: Config Generation
A user runs `i2pbox autoconf_i2pd` interactively. User input must be sanitized before being written to config files. No path traversal, no config injection.

## Functional Requirements

### FR-01: Memory Safety
- No buffer overflows in any input parsing (filenames, base64, regex, user strings)
- No use-after-free in key buffer management (especially `vain.cpp` DELKEYBUFS macro)
- No double-free when error paths exit early
- All `new[]` allocations matched with `delete[]` on every code path
- Stack-allocated buffers have bounds checking

### FR-02: Cryptographic Correctness
- Key generation uses CSPRNG (`RAND_bytes` or equivalent)
- No hardcoded keys, nonces, or seeds
- Signature operations use correct algorithms for the key type
- No timing side-channels in signature verification (constant-time comparison)
- `NameToSigType()` returns correct type for all valid inputs, rejects invalid

### FR-03: Input Validation
- All filenames validated before `open()` — no path traversal beyond intended directory
- Base64 input decoded safely — no buffer overflow on malformed input
- Regex patterns compiled with error handling — no ReDoS (catastrophic backtracking)
- Integer inputs (`atoi`, `stoi`) checked for overflow and range
- `argc`/`argv` bounds checked before every access

### FR-04: Build Hardening
- Binary compiled with `-fstack-protector-strong`
- PIE (Position Independent Executable) enabled
- RELRO (full) enabled
- No executable stack
- ASLR compatible
- No `-Wno-*` suppressing security-relevant warnings

### FR-05: File Permissions
- Generated key files created with `0600` permissions (owner-only read/write)
- No world-readable private key output
- Temporary files (if any) use secure creation patterns

### FR-06: Error Handling
- All OpenSSL return values checked
- All file I/O operations checked for failure
- Failed operations do not leak partial sensitive data to stdout/stderr
- Exit codes are non-zero on failure

### FR-07: Thread Safety (vain.cpp)
- Global mutable state (`found`, `FoundNonce`, `hashescounter`, `foundAddress`) protected or lock-free
- No data race between vanity search threads
- Thread creation/destruction has no resource leaks

### FR-08: Deprecated API Usage
- `TLSv1_method()` in `famtool.cpp` replaced with `TLS_method()` or removed
- `EVP_PKEY_get1_EC_KEY` usage audited for OpenSSL 3.x compatibility
- No use of deprecated OpenSSL functions without migration plan

## Non-Functional Requirements

### NFR-01: Reproducibility
- Audit findings must be reproducible with exact steps
- Each finding includes: file, line number, code snippet, impact, severity, fix recommendation

### NFR-02: Coverage
- Every `.cpp` and `.hpp` file in scope must have at least one security analysis pass
- Critical paths (key generation, signing, file I/O) must have deeper analysis

### NFR-03: Severity Classification
Each finding classified as:
- **Critical**: Direct key leak, RCE, or crypto bypass
- **High**: Buffer overflow, use-after-free, or weak crypto
- **Medium**: Information leak, missing validation, deprecated API
- **Low**: Code quality, missing hardening, minor leak

## Key Entities

- **PrivateKeys**: I2P identity key material — the most sensitive data
- **Signature**: Cryptographic signature over router info or host records
- **Certificate**: X.509 family certificate (ECDSA-P256)
- **RouterInfo**: Signed router descriptor with network addresses
- **Config**: i2pd.conf generated from user input

## Assumptions

- i2pd upstream library (`libi2pd.a`) is treated as a black box — only interface-level issues reported
- OpenSSL version on build system is 1.1.1+ or 3.x
- Target platform is Linux x86_64 (primary), with cross-platform notes where relevant
- Build system uses GCC or Clang with C++17 support
- The binary is distributed as a pre-built tarball (`i2pbox-linux-x86_64.tar.gz`)

## Success Criteria

1. Every source file in scope has been analyzed for at least the vulnerability categories in FR-01 through FR-08
2. All findings are documented with file:line references and fix recommendations
3. Critical and High findings have proof-of-concept test cases where feasible
4. Build system hardening flags are verified via `checksec` or equivalent
5. A summary report categorizes findings by severity and affected subcommand

## Dependencies

- OpenSSL development headers (build-time)
- Boost program_options (build-time)
- i2pd source (submodule, build-time)
- `checksec` or `readelf` for binary analysis
- `valgrind` or `AddressSanitizer` for memory safety testing
