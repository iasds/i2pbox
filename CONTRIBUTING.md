# Contributing to i2pbox

Thanks for helping. i2pbox merges the 14 i2pd-tools into one binary while
preserving their behavior, so changes must stay low-risk and well-tested.

## Development loop

```bash
git clone --recurse-submodules https://github.com/iasds/i2pbox.git
cd i2pbox
make -j2            # builds libi2pd.a first (~2 min), then i2pbox
make test           # regression suite (needs GNU coreutils)
```

Use `-j2` (or `-j$(nproc)`) on your own machine; CI uses `nproc`.

## Before submitting

1. `make test` passes on a normal build.
2. The ASan/UBSan build passes (what CI runs):

   ```bash
   make CXXFLAGS='-Wall -Wextra -std=c++17 -O1 -g -fno-omit-frame-pointer \
     -fsanitize=address,undefined -D_FORTIFY_SOURCE=2 -fPIE -Wformat \
     -Wformat-security -Wno-unused-parameter' \
     LDFLAGS='-fsanitize=address,undefined -Wl,-z,relro,-z,now \
     -Wl,-z,noexecstack -pie' test
   ```

3. New behavior gets covered in `tests/test_cli.sh` (prefer cross-tool
   interoperability assertions and golden vectors over exit-code-only checks).

## Style

- C++17, `-Wall -Wextra` clean, no new warnings.
- Preserve upstream i2pd-tools behavior unless the change is deliberate and
  documented (see the keygen RSA fallback in the README).
- Hardening matters: key files are 0600, buffers are cleansed with
  `OPENSSL_cleanse`, untrusted input is validated before use.
- Keep changes locally scoped; avoid broad rewrites and cosmetic churn.

## Commit messages

Follow the existing conventional style: `fix:`, `feat:`, `docs:`,
`chore:`, `build:`, `test:` prefixes, with a short summary line.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). Do not open
a public issue for an active vulnerability.
