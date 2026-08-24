# secure-secrets-vault

![Python](https://img.shields.io/badge/python-3.12+-blue)
![Tests](https://img.shields.io/badge/tests-88%20passing-brightgreen)
![Type check](https://img.shields.io/badge/mypy-strict-blueviolet)
![License](https://img.shields.io/badge/license-MIT-green)

**Languages:** **English** · [Русский](README_RU.md)

A local, encrypted CLI secrets manager. Passwords, API keys, and private notes live in a single
binary file encrypted with AES-256-GCM, keyed through Argon2id. The crypto primitives come from
audited libraries (`cryptography`, `argon2-cffi`); everything around them — the binary format,
atomic writes with file locking, rollback detection, the CLI — is implemented by hand, with no
cloud, no sync, and no network stack anywhere in the codebase.

> **What this is (and isn't).** This is a **local file**, not a service: there is no browser
> integration, no autofill, no team sharing, no sync between devices — all explicitly out of scope.
> It also does not protect against keyloggers, malware, or anyone who already controls your running
> machine; see [Security model & limitations](#security-model--limitations).

---

## Table of contents

- [Quickstart](#quickstart)
- [Highlights](#highlights)
- [Storage format](#storage-format)
- [Project structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Export & import](#export--import)
- [Security model & limitations](#security-model--limitations)
- [Testing](#testing)
- [Development](#development)
- [Roadmap](#roadmap)
- [FAQ](#faq)
- [License](#license)

## Quickstart

If you just want to see it run, here's the whole loop end to end:

```bash
# 1. install
uv sync          # or: pip install -e .

# 2. create your vault (asks for a master password)
vault init

# 3. store a secret
vault add github --username octocat     # secret is prompted, never echoed

# 4. retrieve it — copies to clipboard, auto-clears in ~20 s
vault get github

# or print it instead of copying
vault get github --print
```

Everything runs locally on one machine — no accounts, no API keys, no daemons left behind after
a command finishes.

## Highlights

- **Audited primitives only.** AES-256-GCM comes from pyca `cryptography`; Argon2id from the
  reference `argon2-cffi` bindings. Nothing cryptographic is hand-rolled — hand-rolled crypto is
  how silent vulnerabilities are born, and none of them show up in unit tests.
- **Crash-safe writes.** Every save goes temp file → `fsync` → `os.replace`. A power cut mid-save
  leaves either the old vault or the new one, never a torn half-file.
- **Multi-process safe.** An advisory file lock covers the entire read-decrypt-mutate-encrypt-write
  cycle, including the revision sidecar, with a structured `VaultBusyError` timeout instead of a
  hung process.
- **Rollback detection.** Every write bumps a monotonic counter stored in the header *and* in a
  sidecar file; if the vault is ever replaced by an older copy, you get an explicit warning.
  Detection, not prevention — and documented as such.
- **Oracle-safe errors.** Wrong password and corrupted ciphertext produce identical messages and
  identical exit codes; structural damage produces a single generic message. Errors leak nothing
  scriptable.
- **Honest plaintext escape hatch.** `--unsafe-plaintext-json` exists for migration, but on pipes/CI
  it requires two independent confirmation factors (`--yes-i-understand` AND a literal `y` on stdin).
- **Typed end to end.** Pydantic v2 schemas everywhere, `mypy --strict` enforced clean.

## Storage format

One binary file (default `~/.secure_vault/vault.enc`). Header fields before the nonce are bound
into the ciphertext as AEAD additional data — tampering with any of them breaks decryption:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic `b"SSV\x00"` | exports use `b"SSVE"` |
| 4 | 1 | format version | = 1 |
| 5 | 1 | kdf_type | `0x01` = Argon2id, protocol constant |
| 6 | 16 | salt | generated once at `init` |
| 22 | 1 | argon2_time_cost | validated range at read time |
| 23 | 4 | argon2_memory_cost_kib | big-endian |
| 27 | 1 | argon2_parallelism | validated range |
| 28 | 1 | argon2_hash_len | = 32 → 256-bit AES key |
| 29 | 8 | revision_counter | big-endian, monotonic |
| 37 | 12 | AES-GCM nonce | fresh random on every write |
| 49 | N | ciphertext ‖ GCM tag | tag = 16 bytes |

The decrypted payload is JSON-serialized `VaultMetadata`: entries carry `id` (UUID), `title`,
`username`, `secret`, `notes`, `tags`, and timestamps. Full byte-level detail lives in
[ARCHITECTURE.md](ARCHITECTURE.md) §5.

## Project structure

```text
secure-secrets-vault/
├── src/secure_secrets_vault/
│   ├── cli.py               # Typer app: all commands
│   ├── vault.py             # VaultManager — orchestration over crypto + storage
│   ├── crypto.py            # Argon2id KDF + AES-GCM wrappers (thin, by design)
│   ├── storage.py           # binary format, header parsing, atomic write, locking, sidecar
│   ├── models.py            # Pydantic v2: VaultEntry / VaultMetadata / KDFConfig
│   ├── generator.py         # secrets-based password generation
│   ├── clipboard.py         # copy + detached auto-clear spawner
│   ├── clipboard_clearer.py # helper-process entry point (timed clear)
│   ├── password_policy.py   # static common-leaked-passwords list
│   ├── exceptions.py        # error taxonomy (oracle-safe)
│   └── config.py            # paths, protocol constants, KDF ranges
├── tests/                   # crypto, storage/concurrency, vault, e2e CLI
├── ARCHITECTURE.md          # design record: threat model, spec, review history
└── pyproject.toml           # deps + `vault` console entry point
```

Dependency direction is strictly downward: `cli → vault → {crypto, storage, generator,
clipboard} → models`. `crypto.py` and `storage.py` know nothing about each other.

## Requirements

- **Python** 3.12 or newer
- **OS**: Linux, macOS, Windows. POSIX gets real `0600` file permissions and `flock`;
  Windows uses `msvcrt` locking and has no ACL support (see [limitations](#security-model--limitations))
- On Linux, clipboard operations need `xclip` or `xsel` installed
- No GPU, no services, no network access required or attempted

## Installation

```bash
git clone <repo-url> secure-secrets-vault
cd secure-secrets-vault
uv sync          # creates .venv, installs the `vault` command
```

or with plain pip:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Configuration

KDF parameters are set once at `vault init` and stored inside the vault header; they can be
changed later via `vault change-master-password`.

### KDF parameters (`vault init` flags)

| Flag | Default | Allowed range | Description |
|---|---|---|---|
| `--time-cost N` | `3` | 2..10 | Argon2id passes |
| `--memory-cost N` | `65536` | 19456..262144 KiB | memory cost (19..256 MiB); upper bound is deliberate — hostile headers must not OOM you |
| `--parallelism N` | `4` | 1..8 | Argon2id lanes |

Defaults follow the OWASP Password Storage Cheat Sheet for Argon2id (~0.5–1 s unlock on a modern
laptop).

### Environment & paths

| Setting | Default | Description |
|---|---|---|
| `SSV_VAULT_PATH` | `~/.secure_vault/vault.enc` | vault location; every command also takes `--vault-path` |

Derived files live next to the vault: `vault.enc.bak` (one-generation backup),
`vault.enc.rev` (revision sidecar), `vault.enc.lock` (write lock). None of them contain secrets.

## Usage

```
vault init                          # create a new vault, set the master password
vault add <title>                   # add an entry (secret prompted secretly)
vault get <title> [--print]         # copy to clipboard / print to stdout
vault list [--tag TAG]              # list entries without secrets
vault update <title>                # modify an entry
vault delete <title>                # remove an entry
vault generate [--length N]         # strong password generation (no unlock needed)
vault change-master-password        # re-encrypt with a new password + fresh salt
vault status                        # revision, backup path — no password needed
```

Duplicate titles resolve to the latest added entry, with a visible warning. Password strength
(≥ 12 chars, not in the built-in leaked-list) is checked at `init` /
`change-master-password`; the check warns but never hard-blocks (`--i-know-its-weak` overrides).
No network requests are ever made — the leaked-password list ships inside the package.

## Export & import

Encrypted round-trip for backups and machine moves:

```bash
vault export --out backup.enc        # prompts for a separate export password
vault import backup.enc              # into an existing vault...
vault import backup.enc --init-if-missing   # ...or straight into a fresh one
```

Import merges: UUID collisions skip by default (the entry was already imported), duplicate titles
import anyway with an ambiguity warning. `--overwrite-conflicts` switches skips to overwrites —
explicitly, never by default.

There is also a deliberate emergency hatch:

```bash
vault export --out secrets.json --unsafe-plaintext-json secrets.json
```

Unencrypted JSON to a file (never stdout), interactive confirmation on terminals, and on
pipes/CI **both** `--yes-i-understand` AND a literal `y` on stdin. Importing that JSON back is
intentionally out of scope for v1. See [SECURITY.md](SECURITY.md).

## Security model & limitations

Full threat model: [ARCHITECTURE.md](ARCHITECTURE.md) §2. The short, honest version.

**Protected against:** offline attackers holding the file (stolen laptop, leaked backup);
brute-force on weak-ish passwords (memory-hard KDF, capped so hostile headers cannot OOM you);
tampering/corruption/truncation (GCM tag + header bound into AAD); concurrent writers corrupting
data (whole cycle under one lock); accidental rollback to an older copy (revision sidecar).

**Explicitly not protected against:** keyloggers and malware while you type; memory dumps while a
command runs; root/administrator on the machine; an adversary who rolls back the *entire directory*
consistently (sidecar included); clipboard sniffers during the ~20-second window; entry titles
visible in `ps`/shell history.

Platform caveats: `0600` permissions are a no-op on Windows (no ACL is set); the clipboard clearer
is best-effort by nature; every command pays ~0.5–1 s of Argon2id because sessions are stateless
by design — the key lives in memory exactly as long as one operation.

## Testing

```bash
pytest            # 88 tests, a few seconds, no network, no fixtures outside tmp_path
```

The suite targets the failure modes that matter for this kind of tool: bit-flips across every AAD
byte, nonce-uniqueness under a deterministic mock, wrong-password vs corrupted-ciphertext oracle
equivalence, lock release under injected failures, lost-update concurrency (threads + barriers),
corrupted `.rev` handling, tempfile cleanup when process spawn fails, and end-to-end CLI flows
through Typer's test runner.

Randomness is mocked deterministically so nothing flakes. See ARCHITECTURE.md §12 for the mapping
between documented failure modes and regression tests.

## Development

```bash
uv sync --dev                     # editable install + dev tools
uv run pytest -v                  # full suite
uv run mypy --strict src/         # must stay clean at all times
```

The codebase is fully typed. When touching crypto/storage/import paths, read the relevant
ARCHITECTURE.md section first — several rules there (AAD slicing, lock discipline, error-oracle
safety) are enforced by tests and easy to break invisibly. See [CLAUDE.md](CLAUDE.md) for the
full working conventions.

## Roadmap

Rough ordering, not promises:

- **Optional unlocked-session mode** (`vault unlock --timeout`) with a background process holding
  the derived key — a separate architectural surface needing its own threat-model round.
- **Full leaked-password dataset** (several thousand entries) replacing the ~100-entry built-in list.
- **Windows ACL support** for the vault file via `pywin32`, removing the biggest Windows caveat.
- **`vault status --json`** and other scripting-friendly output modes.

## FAQ

**Why not just use KeePassXC / Bitwarden?** Use them — they're excellent products. This project
exists to demonstrate building the *entire* envelope correctly (format, atomicity, locking, CLI
ergonomics, threat modeling), which is the part those tools hide.

**Why not implement AES myself?** Because a subtle nonce-reuse bug passes every unit test while
destroying the security guarantee. Hand-rolled crypto demonstrates the wrong thing. The engineering
around the primitives — atomic writes, locking, rollback detection, oracle-safe errors — is where
this project's work actually is.

**I forgot my master password. Can you recover my data?** No. There is no backdoor, no recovery
key, no "password hint" mechanism. This is the correct behavior for a secrets manager, but it means
a forgotten password means a lost vault. The one-generation `.bak` only helps with corruption, not
with a forgotten password.

**Is the clipboard really safe for 20 seconds?** No — best-effort only. Any process on the machine
can read the clipboard at any moment. Auto-clear narrows the window; it doesn't eliminate it. For
hostile environments, use `--print` and pipe carefully, or don't put the secret through the machine
at all.

**Does it phone home / check passwords against HIBP?** Never. There is zero networking code. The
leaked-password check runs against a small static list shipped inside the package.

**Why does every command take ~1 second?** That's Argon2id doing its job — making brute-force
expensive for everyone including you. Sessions are stateless by design; see the roadmap for a
possible unlocked-session mode.

## License

[MIT](LICENSE) © 2026 ZuroKing
