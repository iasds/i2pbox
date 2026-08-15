# Research: i2pbox Security Audit

## R1: OpenSSL Deprecated API Usage

**Decision**: Flag `TLSv1_method()` and related deprecated APIs as High severity findings.

**Rationale**: `TLSv1_method()` was deprecated in OpenSSL 1.1.0 and removed in OpenSSL 3.0. `famtool.cpp` uses it for `SSL_CTX_new()`. This causes:
- Build failure with OpenSSL 3.x
- Forced use of insecure TLS 1.0 even on older OpenSSL

**Alternatives considered**:
- Replace with `TLS_method()` (generic, negotiates highest version) — recommended fix
- Replace with `TLS_client_method()` — also acceptable

**Files affected**: `famtool.cpp` lines 40, 92

---

## R2: DELKEYBUFS Macro Off-by-One

**Decision**: Critical bug — the macro leaks `KeyBufs[0]`.

**Rationale**: The macro is:
```cpp
#define DELKEYBUFS(S) { \
for (unsigned i = S-1; i--;) \
 delete [] KeyBufs[i]; \
delete [] KeyBufs;}
```
When `S=4`, the loop iterates: i=3→check(2)→delete[2], i=2→check(1)→delete[1], i=1→check(0)→loop ends. So `KeyBufs[0]` and `KeyBufs[3]` are never freed. The loop condition `i--` is post-decrement, so it skips index 0 AND the initial value.

**Fix**: Change to `for (unsigned i = 0; i < S; i++) delete [] KeyBufs[i];`

**Files affected**: `vanity.hpp` line 88-91, used in `vain.cpp` lines 408, 449

---

## R3: famtool.cpp switch Fall-through

**Decision**: High severity — case `'o'` falls through to case `'c'`.

**Rationale**: In `famtool.cpp` line 176-179:
```cpp
case 'o':
    outfile = std::string(argv[optind-1]);
case 'c':
    certfile = std::string(argv[optind-1]);
    break;
```
Missing `break` after `'o'` means `-o filename` also sets `certfile` to the same value, and `-c` overwrites `outfile`.

**Fix**: Add `break;` after line 177.

**Files affected**: `famtool.cpp` line 177

---

## R4: autoconf_i2pd.cpp Recursive Stack Overflow

**Decision**: Medium severity — unbounded recursion in `AskYN()` and `GetLanguage()`.

**Rationale**: Both functions call themselves on invalid input with no depth limit. A user holding down a key could cause stack overflow. `IsOnlyYggdrasil()` has the same pattern.

**Fix**: Replace recursion with `while(true)` loop.

**Files affected**: `autoconf_i2pd.cpp` lines 110-137, 139-152

---

## R5: keyinfo.cpp Missing argv Bounds Check

**Decision**: Medium severity — `argv[optind]` accessed without checking `optind < argc`.

**Rationale**: If user runs `i2pbox keyinfo -v` without a filename, `optind` may equal `argc`, and `argv[optind]` is undefined behavior (likely null or garbage).

**Fix**: Add `if (optind >= argc) return printHelp(argv[0], -1);` before line 59.

**Files affected**: `keyinfo.cpp` line 59

---

## R6: Vain.cpp Thread Safety — Global Mutable State

**Decision**: High severity — data races on `found`, `FoundNonce`, `hashescounter`, `foundAddress`.

**Rationale**: Multiple threads read/write these globals concurrently without synchronization:
- `found` (bool) — read by all threads, written by winner
- `FoundNonce` (uint32_t) — same
- `hashescounter` (unsigned long long) — incremented by all threads
- `foundAddress` (std::string) — written by winner, read after join

The `std::string` assignment is particularly dangerous — concurrent write is UB.

**Fix**: Use `std::atomic<bool>`, `std::atomic<uint32_t>`, `std::atomic<unsigned long long>`. For `foundAddress`, use a mutex or write only after join.

**Files affected**: `vanity.hpp` lines 62-73, `vain.cpp`

---

## R7: Build Hardening Flags

**Decision**: Medium severity — Makefile lacks security-hardening flags.

**Rationale**: Current flags: `-Wall -std=c++17 -O2 -g`. Missing:
- `-fstack-protector-strong` (stack canaries)
- `-D_FORTIFY_SOURCE=2` (buffer overflow detection)
- `-pie` (position-independent executable)
- `-Wl,-z,relro,-z,now` (full RELRO)
- `-Wl,-z,noexecstack` (no executable stack)

**Fix**: Add these flags to CXXFLAGS and LDFLAGS.

**Files affected**: `Makefile`

---

## R8: Key File Permissions

**Decision**: Medium severity — generated key files use default umask permissions.

**Rationale**: `keygen.cpp` uses `std::ofstream` which creates files with default permissions (typically 0644). Private key files should be 0600.

**Fix**: Use `open()` with mode 0600, then `fdopen()`, or call `fchmod()` after creation.

**Files affected**: `keygen.cpp` line 22, `offlinekeys.cpp` line 52, `famtool.cpp` lines 213/219, `vain.cpp` line 445

---

## R9: NameToSigType atoi Fallback

**Decision**: Low severity — `atoi()` on short strings returns 0 for invalid input.

**Rationale**: `common/key.hpp` line 53: `if(keyname.size() <= 2) return atoi(keyname.c_str());`
- `atoi("0")` returns 0 = DSA-SHA1 (valid but potentially unintended)
- `atoi("xx")` returns 0 = DSA-SHA1 (silent misinterpretation)
- `atoi("")` returns 0

**Fix**: Use `std::stoi` with try/catch, or validate the string is all digits first.

**Files affected**: `common/key.hpp` line 53

---

## R10: i2pbase64.cpp File Descriptor Leak on Error

**Decision**: Low severity — `infile` opened but not closed on early return.

**Rationale**: If `open()` succeeds but the decode/encode function returns error, `close(infile)` is still called. However, if `argc - optind > 1` returns early, `infile` is 0 (stdin) and `close(0)` is called, which closes stdin.

**Fix**: Only close `infile` if it was actually opened (i.e., `infile != 0`).

**Files affected**: `i2pbase64.cpp` line 92
