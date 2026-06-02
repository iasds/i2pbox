# i2pbox Security Audit Report

**Date**: 2026-06-02
**Auditor**: Sophia (AI)
**Scope**: All i2pbox source files (14 tools, 3 headers, Makefile)
**Build**: C++17, OpenSSL, static-linked libi2pd.a

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 4 |
| Medium | 5 |
| Low | 3 |
| **Total** | **14** |

The most dangerous findings are **private key material leakage through core dumps and world-readable files** (Critical), and **thread-unsafe global state in vanity address generation** (High). Several findings are inherited from upstream i2pd-tools but amplified by i2pbox's single-binary design.

---

## Critical Findings

### C-01: Private Key Files Created World-Readable

**Severity**: Critical
**Files**: `keygen.cpp:22`, `offlinekeys.cpp:52`, `vain.cpp:445`, `famtool.cpp:213,219`
**Impact**: Any user on the system can read generated private keys.

**Description**: All key-generation code paths use `std::ofstream` which creates files with default umask permissions (typically 0644). A multi-user system or shared hosting environment exposes all generated I2P private keys.

```cpp
// keygen.cpp:22 — creates file with default permissions
std::ofstream f (argv[1], std::ofstream::binary | std::ofstream::out);
```

**Fix**: After file creation, set permissions:
```cpp
#include <sys/stat.h>
// ... after ofstream creation ...
chmod(argv[1], 0600);
```
Or use `open()` with explicit mode then `fdopen()`.

---

### C-02: Private Key Material Not Zeroed After Use

**Severity**: Critical
**Files**: `keygen.cpp:26-29`, `regaddr.cpp:23-24`, `regaddr_3ld.cpp:29-30,63-64,105-106`, `regaddralias.cpp:23-24,46-47`, `famtool.cpp:311-312`
**Impact**: Key material persists in freed heap memory, extractable via core dump, /proc/mem, or memory forensics.

**Description**: Private key buffers are `delete[]`'d without zeroing first. The `FromBuffer()` pattern reads keys into a `new uint8_t[]` buffer, uses it, then `delete[]` without `memset`:

```cpp
uint8_t * buf = new uint8_t[len];
s.read ((char *)buf, len);
keys.FromBuffer (buf, len);
// ... use keys ...
delete[] buf;  // buf still contains key material
```

**Fix**: Add `explicit_bzero(buf, len)` or `OPENSSL_cleanse(buf, len)` before `delete[]`.

---

## High Findings

### H-01: famtool Uses Deprecated TLSv1_method()

**Severity**: High
**File**: `famtool.cpp:40,92`
**Impact**: Compilation failure with OpenSSL 3.x. If compiled with older OpenSSL, forces TLS 1.0 which is broken.

```cpp
SSL_CTX * ctx = SSL_CTX_new (TLSv1_method ());  // deprecated since OpenSSL 1.1.0
```

**Fix**: Replace with `TLS_method()` (negotiates highest mutually supported version).

---

### H-02: famtool switch Fall-through — case 'o' Missing break

**Severity**: High
**File**: `famtool.cpp:176-179`
**Impact**: `-o` flag also sets `certfile`, `-c` overwrites `outfile`. Silent data corruption.

```cpp
case 'o':
    outfile = std::string(argv[optind-1]);
    // MISSING: break;
case 'c':
    certfile = std::string(argv[optind-1]);
    break;
```

**Fix**: Add `break;` after line 177.

---

### H-03: DELKEYBUFS Macro Off-by-One — Memory Leak + Double-Free

**Severity**: High
**File**: `vanity.hpp:88-91`
**Impact**: `KeyBufs[0]` never freed (memory leak). `KeyBufs[S-1]` freed twice (double-free/UB).

```cpp
#define DELKEYBUFS(S) { \
for (unsigned i = S-1; i--;) \  // post-decrement: skips i=0 AND i=S-1
 delete [] KeyBufs[i]; \
delete [] KeyBufs;}
```

When `S=4`: loop iterates i=3→delete[2], i=2→delete[1], i=1→check(0)→exit. `KeyBufs[0]` leaked, `KeyBufs[3]` never freed by loop (only by the final `delete[] KeyBufs` which frees the array of pointers, not the pointed-to buffers).

**Fix**:
```cpp
#define DELKEYBUFS(S) { \
for (unsigned i = 0; i < (unsigned)(S); i++) \
 delete [] KeyBufs[i]; \
delete [] KeyBufs;}
```

---

### H-04: Thread Data Races in vain.cpp

**Severity**: High
**Files**: `vanity.hpp:62-73`, `vain.cpp` (throughout)
**Impact**: Undefined behavior. Threads read/write shared globals without synchronization.

**Affected variables**:
- `found` (bool) — written by winning thread, read by all
- `FoundNonce` (uint32_t) — same
- `hashescounter` (unsigned long long) — incremented by all threads
- `foundAddress` (std::string) — assigned by winning thread (std::string assignment is NOT atomic)

```cpp
static bool found=false;                    // data race
static uint32_t FoundNonce=0;               // data race
static unsigned long long hashescounter;     // data race
static std::string foundAddress{};           // data race + UB on std::string
```

**Fix**: Use `std::atomic<bool>`, `std::atomic<uint32_t>`, `std::atomic<unsigned long long>`. For `foundAddress`, write result only after `thread::join()` using a dedicated output variable protected by mutex.

---

## Medium Findings

### M-01: keyinfo.cpp Missing argv Bounds Check

**Severity**: Medium
**File**: `keyinfo.cpp:59`
**Impact**: `i2pbox keyinfo -v` (no filename) accesses `argv[optind]` when `optind >= argc` — undefined behavior.

```cpp
std::string fname(argv[optind]);  // no check that optind < argc
```

**Fix**: Add `if (optind >= argc) return printHelp(argv[0], -1);` before line 59.

---

### M-02: autoconf_i2pd.cpp Recursive Stack Overflow

**Severity**: Medium
**File**: `autoconf_i2pd.cpp:110-137,139-152`
**Impact**: `AskYN()`, `GetLanguage()`, `IsOnlyYggdrasil()` recurse on invalid input with no depth limit.

```cpp
bool AskYN(void) noexcept {
    // ...
    default:
        return AskYN();  // unbounded recursion
}
```

**Fix**: Replace with `while(true)` loop:
```cpp
bool AskYN() noexcept {
    while (true) {
        char answ;
        std::cout << " ? (y/n) ";
        std::cin >> answ;
        CIN_CLEAR;
        switch(answ) {
            case 'y': case 'Y': return true;
            case 'n': case 'N': return false;
        }
    }
}
```

---

### M-03: i2pbase64.cpp Closes stdin on Early Return

**Severity**: Medium
**File**: `i2pbase64.cpp:92`
**Impact**: If no file argument given, `infile=0` (stdin). On error path, `close(0)` closes stdin.

```cpp
int infile = 0;  // stdin
// ... if no file arg, infile stays 0 ...
close(infile);  // closes stdin even if infile was never opened
```

**Fix**: Only close if `infile > 0`:
```cpp
if (infile > 0) close(infile);
```

---

### M-04: verifyhost.cpp Memory Leak on Double Allocation

**Severity**: Medium
**File**: `verifyhost.cpp:49,76`
**Impact**: If `olddest` is present, `signature` is allocated twice. First allocation at line 49 is leaked when overwritten at line 76.

```cpp
uint8_t * signature = new uint8_t[signatureLen];  // line 49
// ...
if (str.find ("olddest=") != std::string::npos) {
    signatureLen = OldIdentity.GetSignatureLen ();
    signature = new uint8_t[signatureLen];  // line 76 — leaks line 49's allocation
```

**Fix**: `delete[] signature;` before the second allocation, or restructure to use a single allocation with max size.

---

### M-05: x25519.cpp Global Variable `len` — Not Thread-Safe

**Severity**: Medium
**File**: `x25519.cpp:9`
**Impact**: `size_t len = KEYSIZE;` is a global modified by `EVP_PKEY_get_raw_public_key()` and `EVP_PKEY_get_raw_private_key()`. If called from multiple threads, data race.

```cpp
size_t len = KEYSIZE;  // global, modified by OpenSSL calls
```

**Fix**: Make `len` local to `getKeyPair()`.

---

## Low Findings

### L-01: NameToSigType Uses atoi — Silent Misinterpretation

**Severity**: Low
**File**: `common/key.hpp:53`
**Impact**: `atoi("xx")` returns 0 = DSA-SHA1. Invalid input silently mapped to weakest key type.

```cpp
if(keyname.size() <= 2) return atoi(keyname.c_str());
```

**Fix**: Validate digits first or use `std::stoi` with exception handling.

---

### L-02: famtool.cpp X509 Certificate — Hardcoded Expiry (10 years)

**Severity**: Low
**File**: `famtool.cpp:249`
**Impact**: Family certificates valid for 10 years with no revocation mechanism. Compromised key stays valid.

```cpp
X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*365*10);
```

**Fix**: Make configurable, document recommended shorter validity.

---

### L-03: Makefile Lacks -Wextra and Security Hardening Flags

**Severity**: Low
**File**: `Makefile:11`
**Impact**: Missed warnings. No stack canaries, no FORTIFY_SOURCE, no PIE, no full RELRO.

**Current**: `CXXFLAGS := -Wall -std=c++17 -O2`

**Fix**:
```makefile
CXXFLAGS := -Wall -Wextra -std=c++17 -O2 \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -fPIE -Wformat -Wformat-security
LDFLAGS += -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie
```

---

## Additional Observations (Not Vulnerabilities)

### O-01: RSA Key Types Listed but Not Functional
`vain.cpp:330-336` — RSA/GOST types listed in switch but print "Sorry, i don't can generate" and return 0 (success, not error). Misleading exit code.

### O-02: autoconf_i2pd Config Injection Risk
User input written directly to `.conf` without sanitization. A malicious path like `../../etc/cron.d/evil` could be used for path traversal in config values. Low risk since user controls their own config, but worth noting.

### O-03: No ASLR/PIE in Current Binary
The current Makefile does not produce a PIE binary, reducing ASLR effectiveness.

---

## Remediation Checklist

- [ ] **C-01**: Set 0600 on all key file outputs
- [ ] **C-02**: `OPENSSL_cleanse()` all key buffers before free
- [ ] **H-01**: Replace `TLSv1_method()` with `TLS_method()`
- [ ] **H-02**: Add `break` in famtool case 'o'
- [ ] **H-03**: Fix DELKEYBUFS macro loop bounds
- [ ] **H-04**: Use atomics for vain.cpp shared state
- [ ] **M-01**: Add optind bounds check in keyinfo
- [ ] **M-02**: Replace recursion with loops in autoconf
- [ ] **M-03**: Guard close() in i2pbase64
- [ ] **M-04**: Fix signature double-allocation in verifyhost
- [ ] **M-05**: Make x25519 len variable local
- [ ] **L-01**: Replace atoi with safe parsing in NameToSigType
- [ ] **L-02**: Make certificate expiry configurable
- [ ] **L-03**: Add hardening flags to Makefile
