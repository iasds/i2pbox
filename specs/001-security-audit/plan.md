# Implementation Plan: i2pbox Security Audit

## Overview

Execute a comprehensive security audit of the i2pbox codebase, covering all 14 subcommands, shared headers, and the build system. Produce a final report with severity-classified findings, proof-of-concept tests where feasible, and fix recommendations.

## Technical Context

- **Language**: C++17
- **Crypto library**: OpenSSL (1.1.x / 3.x)
- **Build**: GNU Make, static linking to libi2pd.a
- **Platform**: Linux x86_64 primary
- **Source files**: 14 .cpp, 3 .hpp/.h, 1 Makefile
- **Known issues from Phase 0 research**: 10 findings pre-identified (R1–R10)

## Tasks

### IMP-01: Build System Hardening Audit
**Priority**: High
**Files**: `Makefile`
**What**:
- Verify current compiler/linker flags
- Check for `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-pie`, full RELRO, noexecstack
- Run `checksec` on existing binary if available
**Deliverable**: Findings on build hardening gaps + patched Makefile
**Acceptance**: Binary passes `checksec` with all green after fix

### IMP-02: famtool.cpp — OpenSSL & Switch Fall-through
**Priority**: Critical
**Files**: `famtool.cpp`
**What**:
- Verify `TLSv1_method()` deprecation (R1)
- Verify case `'o'` fall-through (R3)
- Check all OpenSSL return values for error handling
- Check for memory leaks in SSL_CTX/SSL/EVP_PKEY lifecycle
**Deliverable**: Findings + fixes for all famtool issues
**Acceptance**: `famtool -g`, `-s`, `-V` paths have no UB or leaks

### IMP-03: vain.cpp — Thread Safety & Memory
**Priority**: Critical
**Files**: `vain.cpp`, `vanity.hpp`
**What**:
- Verify DELKEYBUFS off-by-one (R2)
- Verify data races on global state (R6)
- Check for use-after-free in key buffer lifecycle
- Verify `std::regex` usage is thread-safe (C++11 guarantees this, but verify)
- Check integer overflow in nonce counter (`uint32_t` wrapping)
**Deliverable**: Findings + thread-safe rewrite of global state
**Acceptance**: `vain test -t 8` runs without TSan warnings

### IMP-04: keygen.cpp & offlinekeys.cpp — Key File Security
**Priority**: High
**Files**: `keygen.cpp`, `offlinekeys.cpp`
**What**:
- Verify key file permissions (R8)
- Check for key material in core dumps (`mlock`/`MADV_DONTDUMP`)
- Verify buffer cleanup after write (`memset` on sensitive buffers)
- Check error paths for partial key leakage
**Deliverable**: Findings + file permission fixes
**Acceptance**: Generated files are 0600, no key residue in freed memory

### IMP-05: keyinfo.cpp — Input Validation & Info Leak
**Priority**: Medium
**Files**: `keyinfo.cpp`
**What**:
- Verify argv bounds check (R5)
- Check `-p` (print private key) for unintended output channels
- Verify `FromBuffer` handles truncated/malformed key files
- Check for format string issues in `SigTypeToName` output
**Deliverable**: Findings + input validation fixes
**Acceptance**: All edge cases (no file, empty file, truncated file, missing args) handled cleanly

### IMP-06: regaddr.cpp / regaddr_3ld.cpp / regaddralias.cpp — Signing Operations
**Priority**: High
**Files**: `regaddr.cpp`, `regaddr_3ld.cpp`, `regaddralias.cpp`
**What**:
- Verify signature buffer sizing (no overflow)
- Check for TOCTOU in file read operations
- Verify `keys.Sign()` error handling
- Check for memory leaks in signing buffers
**Deliverable**: Findings
**Acceptance**: All three tools handle malformed key files without crash

### IMP-07: verifyhost.cpp — Signature Verification
**Priority**: High
**Files**: `verifyhost.cpp`
**What**:
- Verify `Base64ToByteStream` bounds checking on untrusted input
- Check for buffer overflow in `signature = new uint8_t[signatureLen]` if `signatureLen` is attacker-controlled
- Verify `Identity.Verify()` error handling
- Check for double-free (signature allocated twice in olddest path)
**Deliverable**: Findings
**Acceptance**: Malformed host records do not cause crash or memory corruption

### IMP-08: i2pbase64.cpp — File Descriptor & Buffer Safety
**Priority**: Medium
**Files**: `i2pbase64.cpp`
**What**:
- Verify fd leak on error paths (R10)
- Check stack buffer sizes (`inbuf[BUFFSZ*4]`, `outbuf[BUFFSZ*3]`) for overflow
- Verify `Base64ToByteStream` output bounds
**Deliverable**: Findings + fd handling fix
**Acceptance**: Pipe large data through encode/decode without leak or overflow

### IMP-09: autoconf_i2pd.cpp — Input Injection & Stack Overflow
**Priority**: Medium
**Files**: `autoconf_i2pd.cpp`
**What**:
- Verify recursive stack overflow in AskYN/GetLanguage (R4)
- Check for config injection (user input written directly to .conf)
- Verify regex DoS on `Regexps::path`
- Check `std::cin >>` for buffer overflow on long input
**Deliverable**: Findings + recursion-to-loop fix
**Acceptance**: Long input strings and invalid input handled without crash

### IMP-10: x25519.cpp / b33address.cpp — Crypto Output & Input
**Priority**: Low
**Files**: `x25519.cpp`, `b33address.cpp`
**What**:
- Verify X25519 key generation uses CSPRNG
- Check for private key leakage in output
- Verify `FromBase64` handles malformed input in b33address
**Deliverable**: Findings
**Acceptance**: Malformed base64 input doesn't crash b33address

### IMP-11: common/key.hpp — Type Parsing
**Priority**: Low
**Files**: `common/key.hpp`
**What**:
- Verify `atoi` fallback behavior (R9)
- Check `NameToSigType` for all valid/invalid inputs
- Verify `SigTypeToName` doesn't leak info on unknown types
**Deliverable**: Findings + safer type parsing
**Acceptance**: Invalid type names return error, not silent default

### IMP-12: Static Analysis & Dynamic Testing
**Priority**: High
**What**:
- Compile with AddressSanitizer + UndefinedBehaviorSanitizer
- Run each subcommand with fuzzed inputs
- Run valgrind on key generation and signing operations
- Check for compiler warnings with `-Wall -Wextra -Werror`
**Deliverable**: ASan/UBSan/valgrind reports
**Acceptance**: Zero sanitizer warnings on clean runs

### IMP-13: Final Report
**Priority**: Critical
**What**:
- Consolidate all findings into severity-classified report
- Include file:line references, code snippets, impact, fix recommendations
- Generate summary statistics (Critical/High/Medium/Low counts)
- Produce remediation checklist
**Deliverable**: `specs/001-security-audit/report.md`
**Acceptance**: Every source file has at least one analysis entry

## Execution Order

```
Phase 1 (Static — can run in parallel):
  IMP-01 (Makefile) + IMP-02 (famtool) + IMP-03 (vain)
  IMP-04 (keygen/offlinekeys) + IMP-05 (keyinfo)
  IMP-06 (regaddr*) + IMP-07 (verifyhost)
  IMP-08 (i2pbase64) + IMP-09 (autoconf)
  IMP-10 (x25519/b33) + IMP-11 (key.hpp)

Phase 2 (Dynamic — needs clean build):
  IMP-12 (ASan/UBSan/valgrind)

Phase 3 (Report):
  IMP-13 (Final report)
```

## Commit Messages

- `IMP-01`: `security: add build hardening flags (PIE, RELRO, stack-protector)`
- `IMP-02`: `security: fix famtool TLSv1 deprecation and switch fall-through`
- `IMP-03`: `security: fix vain thread safety and DELKEYBUFS off-by-one`
- `IMP-04`: `security: enforce 0600 permissions on generated key files`
- `IMP-05`: `security: add argv bounds check in keyinfo`
- `IMP-06`: `security: validate signature buffer sizes in regaddr tools`
- `IMP-07`: `security: add bounds checking in verifyhost input parsing`
- `IMP-08`: `security: fix fd leak and buffer bounds in i2pbase64`
- `IMP-09`: `security: replace recursive calls with loops in autoconf`
- `IMP-10`: `security: validate x25519/b33 input handling`
- `IMP-11`: `security: replace atoi with safe integer parsing in NameToSigType`
- `IMP-12`: `security: run ASan/UBSan/valgrind dynamic analysis`
- `IMP-13`: `security: add comprehensive audit report`
