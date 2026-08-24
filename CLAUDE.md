# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project

`secure-secrets-vault` — a local, encrypted CLI secrets manager (Python ≥ 3.12).
AES-256-GCM + Argon2id via audited libraries (`cryptography`, `argon2-cffi`);
everything around them (binary format, atomic write, locking, CLI) is
hand-written. The design record is **ARCHITECTURE.md** (English) /
**ARCHITECTURE_ru.md** (Russian) — read §5, §6, §10 before touching crypto,
storage, or import/export code. §14 lists deliberate deviations between the
spec and the implementation; keep it accurate.

## Commands

```bash
uv sync --dev                      # install deps into .venv
uv run pytest -v                   # full test suite (baseline: all passing)
uv run pytest tests/test_storage.py -v   # single file
uv run mypy --strict src/          # must stay clean at all times
uv run vault --help                # run the CLI locally
```

No tox/ruff config exists yet. Do not add dependencies without asking.

## Non-negotiable security rules

These are enforced by the spec (ARCHITECTURE.md) and by existing tests.
Violating any of them is a bug even if tests stay green:

- **Secrets/passwords never appear** in exceptions, tracebacks, logs, exit
  codes, `argv`, or error messages. When chaining exceptions from Pydantic
  validation of decrypted data, do NOT use `from exc` (ValidationError text
  contains input values).
- **AAD = raw header bytes `[0:37)`** taken as a slice of bytes already read
  from disk on decrypt — never reconstructed from parsed fields.
- **Error oracle safety:** wrong-password and corrupted-ciphertext share one
  message and one exit code; structural errors share a different single
  message. Never add detail that distinguishes within a class.
- **Header validation order is fixed:** magic → version → kdf_type → KDF
  ranges, all before Argon2id runs (OOM-DoS protection). Ranges live in
  `config.py`.
- **Writes go through `storage.update_vault`**: read → parse → decrypt →
  mutate → encrypt all inside the lock; sidecar `.rev` written strictly after
  `os.replace`; lock released in `finally`. Never move decrypt outside the
  critical section (lost-update regression test exists).
- Use `secrets`, not `random`; use `hmac.compare_digest`, not `==`, for
  secret comparison.
- The plaintext export path (`--unsafe-plaintext-json`) requires both
  confirmation factors on non-tty. Do not weaken it.

## Repository hygiene

- `.gitignore` blocks vault artifacts (`*.enc`, `*.enc.bak`, `*.enc.rev`,
  `*.enc.lock`). Never commit real vault files, temp files containing secret
  hashes, or anything produced by running the CLI against a real vault.
- Tests must use `tmp_path` fixtures, never real paths like
  `~/.secure_vault`.

## Testing protocol

- Real `pytest -v` output only — never fabricate or summarize results.
- Randomness in tests is mocked deterministically (e.g. seeded counter over
  `os.urandom`) so tests don't flake.
- Every documented failure mode in ARCHITECTURE.md §12 has a regression test
  (AAD bit flips across all header bytes, lock release under early return,
  lost-update concurrency, corrupted `.rev`, tempfile cleanup on `Popen`
  failure, rollback warning). If you change related behavior, update both
  code and tests together.
- Concurrency tests use threads + barriers; they run on Windows CI-less
  dev boxes, keep timeouts generous.

## Documentation conventions

- Bilingual pairs: README ↔ README_RU, ELI5 ↔ ELI5_ru,
  ARCHITECTURE ↔ ARCHITECTURE_ru, SECURITY ↔ SECURITY_ru. When you change
  meaning in one, mirror it in the other.
- ARCHITECTURE.md uses review-round tags (`[grill-me v2]` … `[grill-me v4]`)
  to explain why decisions exist. New spec changes get a new tag/section, not
  silent rewrites of history.
- If implementation diverges from the spec, either fix the code or document
  the deviation in §14 — never leave them silently inconsistent.

## Environment notes

- Dev machine is Windows (PowerShell 5.1) but code must stay cross-platform:
  POSIX branches use `fcntl`, guarded by `os.name` checks; `mypy --strict`
  runs on Windows, so POSIX-only imports need care.
- Do not edit the Russian-language Markdown files via PowerShell
  `Set-Content`/`Get-Content` pipelines — PowerShell 5.1 mangles UTF-8
  Cyrillic. Use file-editing tools that preserve encoding.
