# AGENTS.md — working conventions for this repo

## General

- Use small, well-tested patches. Keep diffs locally scoped; no broad rewrites or formatting churn.
- Keep `make -Wall -Wextra` clean; no new warnings.
- Preserve upstream `i2pd-tools` behavior unless the change is deliberate and documented.
- Key files are 0600, buffers are cleansed with `OPENSSL_cleanse` after use.

## Build & test

```bash
git clone --recurse-submodules https://github.com/iasds/i2pbox.git
cd i2pbox
make -j$(nproc)        # first build compiles libi2pd.a (~2 min)
make test              # regression suite (needs GNU coreutils, Linux)
make bench             # perf baseline (~2s)
make fuzz-smoke        # local corpus smoke (no clang required)
make fuzz-build && ./tests/fuzz/run_fuzz_smoke.sh 15  # libFuzzer smoke (clang)
make interop           # cross-validate against go-i2p / emissary / i2p-java
```

`make clean && make -j2 && make test` must pass before requesting review. CI runs the suite on both a normal build and an ASan/UBSan build with `detect_leaks=1 halt_on_error=1`.

## Commit & tag signing

- **Every commit pushed to GitHub must be GPG-signed with your local private key.** No unsigned commits on `main` or tags.
- **Every tag must be an annotated, signed tag** (`git tag -s vX.Y.Z -m "i2pbox vX.Y.Z"`), using the same key.
- The repo is configured for this:

  ```ini
  [commit]
    gpgsign = true
  [tag]
    gpgsign = true
  [user]
    signingkey = 8E8379E4C33668439B46C622996DAD4EBDA21312!
  [gpg]
    format = openpgp
    program = gpg
  ```

  Verify before pushing:

  ```bash
  git log --show-signature -1      # Good signature from "iasds <...>"
  git verify-tag vX.Y.Z             # Good signature
  git push --follow-tags            # pushes both commits and tag together
  ```

- Do not generate or commit private keys, tokens, or session strings. Never paste secrets into code, configs, or agent prompts.
- Appending a `Signed-off-by` line is not required for this repo (no DCO).

## Style

- C++17. Commit messages use conventional prefixes: `fix:`, `feat:`, `docs:`, `chore:`, `build:`, `test:` with a short summary line.
- Don't push generated artifacts (`*.o`, `*.d`, `i2pbox`, `dist/`, `i2pd/libi2pd.a`, fuzz `crash-*`/`oom-*` files) — they're gitignored.
