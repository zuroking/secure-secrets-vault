# Security Policy

> Russian version: [SECURITY_ru.md](SECURITY_ru.md)

## Reporting a vulnerability

This is a secrets manager — security reports are taken seriously.

**Please do not report security vulnerabilities through public GitHub
issues.**

Instead, report them privately via [GitHub Security Advisories]
("Security" tab → "Report a vulnerability"), or contact the maintainer
directly if you prefer email.

Include as much of the following as you can:

- The affected component (`crypto.py`, `storage.py`, `vault.py`, `cli.py`,
  `clipboard*.py`) or command
- Step-by-step reproduction or a proof of concept
- Threat-model context: which adversary from the model below applies
- Expected vs. actual behavior

You will get an initial response within 7 days. Fixes for confirmed issues
are released as soon as practical, and you will be credited in the release
notes unless you prefer to stay anonymous.

## Scope: what counts as a vulnerability

Useful reference points — the project's threat model is documented in
[ARCHITECTURE.md](ARCHITECTURE.md) §2, including what the tool **explicitly
does not protect against**. Reports that contradict that documented scope
(e.g., "the master password is asked on every invocation", "titles leak into
`ps` output") will be closed as working-as-documented — but if you believe a
documented decision is wrong, an ARCHITECTURE.md issue is welcome.

In-scope examples:

- Any way to decrypt `vault.enc` faster than brute-forcing Argon2id
- Nonce reuse or key reuse across encryptions under the same password
- AAD not covering header fields (KDF parameter tampering undetected)
- Lock/sidecar races leading to lost updates or revision-counter bypass
- Secrets leaking into error messages, logs, tracebacks, exit codes, or
  process arguments (beyond documented `<title>` argv exposure)
- Plaintext export reachable without both required confirmations

Out of scope:

- Keyloggers, malware, memory dumps, and root attackers on the user's machine
  (explicitly out of the threat model)
- Weak user-chosen master passwords
- Side channels requiring local execution already privileged enough to read
  the vault file directly

## Supported versions

Only the latest tagged release receives security fixes.
