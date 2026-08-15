# Security Policy

i2pbox is a cryptographic toolkit: it handles I2P private keys, generates
cryptographic material, and processes untrusted input (filenames, addresses,
base64, regex patterns). Security issues are taken seriously.

## Reporting a Vulnerability

Please report vulnerabilities **privately** using GitHub's Private
vulnerability reporting for this repository:

1. Open the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Include:
   - The affected command and version (`i2pbox --version`)
   - A minimal reproducer (inputs, flags, environment)
   - Your assessment of impact (key disclosure, DoS, code execution, ...)

Do not open a public issue for an active vulnerability.

## What to expect

- We acknowledge reports as soon as possible.
- Fixes are released as new tags; the fix commit references the advisory
  after it is public.
- There is no bug bounty program, but we credit reporters in the advisory
  when they agree.

## Scope

The in-repo security audit lives in
[`specs/001-security-audit/`](specs/001-security-audit/) (spec, plan, report,
research, requirements checklist). The CI suite runs the regression tests
under AddressSanitizer and UndefinedBehaviorSanitizer on every push.
