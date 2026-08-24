# ARCHITECTURE.md — `secure-secrets-vault`

> Русская версия документа: [ARCHITECTURE_ru.md](ARCHITECTURE_ru.md).

> Status: **v5 — v1 implemented.** This document is the design record
> (v1–v4 = four `grill-me` review rounds); the code in `src/` implements it.
> Deliberate deviations and clarifications discovered during implementation
> are collected in [§14](#14-implementation-status-and-deliberate-deviations).
> Test suite: 88 passing; `mypy --strict` clean.

---

## 1. Purpose and scope

A CLI secrets manager (passwords / API keys / notes) with a local encrypted
store. No cloud, no sync, no network stack.

**Explicitly out of scope:**
- Cross-device sync
- Browser integration / autofill
- Team sharing of secrets
- GUI

---

## 2. Threat model (explicit)

Before talking about AES and Argon2, we need to state explicitly what we
protect against and what we don't. Without this section a "security project"
degrades into security theatre.

### We protect against:
- **An offline attacker holding the `vault.enc` file** (stolen laptop, backup,
  leak from a cloud sync of the folder). Without the master password,
  decryption must be computationally infeasible.
- **Brute-force / dictionary attacks on the master password** — via a
  memory-hard KDF (Argon2id) that makes guessing expensive in hardware terms.
- **File corruption/truncation** — the AEAD tag detects both tampering and
  corruption.
- **Concurrent writes corrupting the vault** — atomic write + file lock
  `[grill-me v2: was claimed but not implemented — see §5 file lock]`.
- **Data loss on power failure during a write** — `fsync` before `os.replace`
  `[grill-me v2, found by OpenCode/F2, missed in v1]`.
- **Detection (not prevention) of rollback to an older vault version** — via a
  monotonic revision counter `[grill-me v2, see §5]`.

### We explicitly do NOT protect against (out of scope, documented anyway):
- Keyloggers or malware on the user's machine at password-entry time.
- Memory dumps / core dumps while the vault is unlocked in the current process.
- Root/administrator access to the running machine.
- **Zeroization of keys/passwords in process memory.** `[grill-me v2: replaces
  the earlier "mlock-like measures" wording.]` CPython provides no zeroization
  guarantees for `str`/`bytes` — values are immutable, copied by the GC, and
  `cryptography` keeps its own copies of the key on the heap. The honest
  position is "we do not protect against this", not a "partially mitigated"
  incorrect claim that does nothing in practice.
- **Preventing rollback attacks** (see above — we detect, we don't prevent;
  full prevention requires trusted external state outside the file, which is
  out of scope for a serverless local CLI).
- Multi-user shared-machine scenarios (file permissions are best-effort via
  `0600` on POSIX; **on Windows this is a no-op** `[grill-me v2]` — no ACL is
  set; document as a known limitation in `--help`).
- Clipboard sniffing by another process, `<title>` leaking through
  `ps`/shell history as metadata, shoulder surfing during `--print`
  `[grill-me v2, TM-5]` — partially mitigated (buffer autoclear, see §8), not
  eliminated; stated explicitly rather than left unsaid.

This is not an excuse to "not bother doing it properly" — it is standard
practice: without an explicit threat model you cannot make a reasoned choice
between "harden X" and "don't bother hardening X".

---

## 3. Key architectural decision: use audited primitives

The crypto primitives (AES-GCM, Argon2id) are **not implemented from
scratch**, but via:

- [`cryptography`](https://cryptography.io/) (pyca) — AES-256-GCM,
  constant-time comparisons, CSPRNG
- [`argon2-cffi`](https://argon2-cffi.readthedocs.io/) — bindings to the
  reference C Argon2 implementation

**Why not "from scratch", unlike the other portfolio projects:** in
`autograd-engine` the goal is understanding what PyTorch does under the hood,
and an implementation error at worst yields a wrong gradient that tests catch
immediately. In a crypto primitive, an error (non-constant-time comparison,
nonce reuse, incorrect padding) is a **silent vulnerability**: it never shows
up in a unit test yet completely destroys the security guarantee. A
hand-rolled AES here would demonstrate not mastery but misunderstanding of
the domain.

What *is* built from scratch in this project: the storage format, the vault
schema, the CLI, the key derivation pipeline, atomic-write logic, session/
timeout handling. That is enough real engineering to make the project
substantive.

---

## 4. Module layout

```
secure_secrets_vault/
├── __init__.py
├── cli.py              # Typer app, commands, Rich output
├── vault.py            # VaultManager — business logic over crypto+storage
├── crypto.py           # KDF, AEAD encrypt/decrypt wrappers over cryptography/argon2-cffi
├── storage.py          # Binary file format, atomic write, backup
├── models.py           # Pydantic v2: VaultEntry, VaultMetadata, VaultConfig
├── generator.py        # Cryptographically strong password generation (`secrets`)
├── clipboard.py        # Clipboard copy with auto-clear
├── clipboard_clearer.py # Detached helper: timed clipboard clear [grill-me v3]
├── exceptions.py       # VaultError, WrongPasswordError, CorruptedVaultError, ...
└── config.py           # Default paths, KDF parameters, constants
```

Dependencies flow strictly downward: `cli.py → vault.py → {crypto.py,
storage.py, generator.py, clipboard.py} → models.py`. `crypto.py` and
`storage.py` know nothing about each other — `vault.py` orchestrates them.

---

## 5. Storage format

One binary file (default `~/.secure_vault/vault.enc`).

```
Offset  Size    Field
0       4       magic bytes b"SSV\x00"
4       1       format version (uint8) = 1
5       1       kdf_type (uint8) — 0x01 = Argon2id (a protocol constant,
                not configurable; pins the argon2-cffi hash type)
6       16      salt (Argon2id, os.urandom(16), see lifecycle below)
22      1       argon2_time_cost (uint8, allowed range see §6)
23      4       argon2_memory_cost_kib (uint32, big-endian, range see §6)
27      1       argon2_parallelism (uint8, range see §6)
28      1       argon2_hash_len (uint8) = 32 (protocol constant)
29      8       revision_counter (uint64, big-endian, monotonically increasing
                on every successful write) [grill-me v2, rollback detection]
37      12      AES-GCM nonce (os.urandom(12), lifecycle see below)
49      N       ciphertext || GCM tag (tag = 16 bytes, appended by cryptography)
```

`[grill-me v2]` Added `kdf_type`, `argon2_hash_len`, `revision_counter`
following both independent `grill-me` runs — their absence in v1 meant that
if `argon2-cffi` defaults changed, old vaults could fail to decrypt with no
migration path, and rollback to an older file version was undetectable.

**Header validation order** `[grill-me v3, OpenCode V2-NEW-9]`: strictly
`magic → version → kdf_type → KDF parameter ranges`, with early return on the
first mismatch. The export format (magic `b"SSVE"`, see §10) must be rejected
at the first step as "not a vault file", not fall through as "bad version" —
magic is checked in full (4 bytes), not as a prefix.

### AAD — exact definition `[grill-me v2, CRITICAL from both agents]`

**AAD = raw header bytes `[0:37)` (offset 0 inclusive to offset 37
exclusive).** Operational rule: `encrypt` serializes the header once into a
byte buffer — the same buffer is simultaneously written to disk as the file
header and passed to AES-GCM as AAD. `decrypt` takes this range as a
**slice of already-read-from-disk bytes**, never reconstructing it from
parsed Pydantic fields `[grill-me v3: reworded per F19 — the previous
wording pushed implementers toward finding a shared object between
encrypt/decrypt instead of a simple byte-slice]`. Any canonicalization bug
(field order, endianness) during reconstruction silently removes protection
against KDF parameter substitution — which is why reconstruction must not
exist at all.

Mandatory tests: flip 1 bit in any byte of `[0:37)` → `decrypt` raises;
separately — flip a byte in the nonce `[37:49)` → also raises (regression
test against someone "optimizing" nonce passing into a separate path)
`[grill-me v3, Claude Code F25]`.

### Salt / Argon2 / nonce — lifecycle `[grill-me v2, agreed with the user]`

- **Salt** is generated once — at `vault init` — and lives for the lifetime
  of the vault. It is regenerated **only** on `change-master-password`
  (see §8).
- **Argon2id runs once per CLI invocation** (one process invocation = one KDF
  call → the derived key serves all encrypt/decrypt operations within that
  invocation).
- **Nonce — fresh `os.urandom(12)` for every single AES-GCM encrypt call**,
  i.e. per file-write operation, not per entry inside the vault (the whole
  `VaultMetadata` is encrypted as one blob in one `encrypt` call). The key is
  reused between writes (salt fixed → KDF does not rerun); the only defense
  against `(key, nonce)` reuse in GCM is nonce randomness per call. Birthday
  bound for a 96-bit nonce: with `w` writes, collision risk ≈ `w² / 2⁹⁷` —
  negligible for a personal vault (even at `10⁶` writes, ~`10⁻²⁰`).

### Revision counter — rollback detection `[grill-me v3: sidecar rewritten after the race found by OpenCode]`

`revision_counter` increments by 1 on every successful write and is included
in the AAD (protected by the tag against tampering without the password). It
detects but does **not prevent** rollback of the file to an older valid
version.

**Sidecar file** — `<vault_path>.rev` (per-vault, derived from the vault path,
not a hardcoded `~/.secure_vault/.last_revision` — otherwise multiple vaults
via `--vault-path` would share one counter and generate false warnings
`[grill-me v3, found by both agents]`). Contains just a number (plaintext,
not a secret).

**Sidecar writing is part of the same critical section as the vault write**,
not a separate operation after unlock: the race exists precisely because in
v2 the sidecar was read/written outside the lock — two parallel `add`s could
both read revision=5, both increment to 6, and the second would quietly
rewrite the sidecar with 6 instead of 7, breaking detection itself
`[grill-me v3, OpenCode V2-NEW-1]`. The current order (see Atomic write
below) holds the lock across the entire cycle: read vault + read sidecar +
write vault + fsync + write sidecar + fsync — one atomic section.

**Honest boundary of the mechanism** `[grill-me v3, OpenCode V2-NEW-2]`: the
sidecar is a plaintext file with no integrity protection of its own, sitting
next to the vault. An attacker with write access to the directory (i.e.
already able to replace `vault.enc` — exactly the rollback scenario) can roll
`.rev` back together with the vault, nulling detection. This is **not a bug
in a specific implementation but a fundamental limitation** of any sidecar
scheme without external trusted state: the mechanism catches **point**
rollback of one file (sync bug, manual mistake), not systematic rollback of
the whole directory by an attacker who already owns that directory. A missing
`.rev` at first run is treated as `revision=0` (not an error).

**Corrupted `.rev` handling and crash gap** `[grill-me v4, follow-up to
V2-NEW-1]`: `.rev` contains only an ASCII decimal number. On parse failure
(not a number, empty, outside `0..2⁶⁴-1`) the file is treated as `0` with a
stderr warning, not as a fatal error — otherwise an attacker could DoS
writes by planting garbage in the sidecar. Corrupted `.rev` never blocks a
write. After a crash between step 7 (`os.replace` of the vault) and step 9
(sidecar write), the next successful write computes
`max(header_rev, sidecar_rev)+1`, producing a gap of 1 (e.g. `6->8`). The
gap is documented as expected and not a bug — the invariant is "revision is
strictly monotonic", not "revision +=1 without gaps".

### Atomic write `[grill-me v4: added finally and writer-side Windows-handle rule; base — v3 lock extended to sidecar]`

1. Open/create `<vault_path>.lock` and take an advisory file lock
   (`fcntl.flock(LOCK_EX)` on POSIX; `msvcrt.locking(LK_LOCK)` in a retry
   loop on Windows) — **with a timeout** (default 10 seconds). On timeout —
   a structured error `VaultBusyError("another operation in progress")`, not
   a raw traceback `[grill-me v3, both agents flagged timeout-less Windows
   semantics as a defect]`. The lock is held across the **entire** cycle
   below, including the sidecar steps — this is the race fix from the
   previous item. **The whole cycle 2–9 runs in a `try/finally`; step 10 is
   in `finally`** `[grill-me v4, follow-up to V2-NEW-1: without finally any
   early-return/exception between steps 3 and 9 would leave the lock held
   until timeout]` — if any step before 7 fails, the sidecar is not written
   at all, and the lock is still released.
2. Read `vault.enc` fully into memory and **close the file handle before
   calling `decrypt`** — the rule applies to readers (`get`/`list`) and
   writers (`add`/`update`/`delete`/`import`) alike `[grill-me v4, extension
   of v3 F18: writers were excluded in v3; on Windows their open handle also
   blocks `os.replace` of a parallel writer]`. Argon2id takes most of the
   operation's time — holding the handle open those seconds creates a Windows
   hazard: `os.replace` fails with `PermissionError` because Windows does not
   open files with `FILE_SHARE_DELETE` by default `[grill-me v3, Claude Code
   F18]`. The writer additionally wraps step 6 in retry-with-backoff
   (3 attempts, exponential pause) against `PermissionError` from a parallel
   reader.
3. Decrypt `vault.enc` (header validation `magic→version→kdf_type→ranges`
   before KDF, see §6). Read `<vault_path>.rev` (or assume `0` if missing;
   corrupted `.rev` → `0` with warning, see above).
4. Copy current `vault.enc` → `vault.enc.bak` (best-effort).
5. Serialize → encrypt (fresh nonce, `revision_counter = max(header revision,
   sidecar revision) + 1` — max guards against desync) → write to
   `vault.enc.tmp`.
6. `f.flush()` + `os.fsync(f.fileno())` on `vault.enc.tmp` **before** rename.
7. `os.replace("vault.enc.tmp", "vault.enc")`.
8. On POSIX — `os.fsync()` on the parent directory fd after rename.
9. **Write `<vault_path>.rev` strictly after step 8 succeeds**, never before
   `[grill-me v3, OpenCode V2-NEW-1: writing before replace creates a false
   alarm forever if a crash happens between steps]`, using the same
   tmp+fsync+replace pattern (the file is tiny, but the principle holds —
   never leave a partially written counter). If steps 5–8 did not complete
   successfully, step 9 is skipped entirely.
10. Release the lock (in `finally`).

**Backup policy**: one generation deep (`vault.enc.bak` is overwritten by
every save). Recovery is manual: `cp vault.enc.bak vault.enc`; document in
`--help`/README.

**Decrypted plaintext** — JSON serialization of `VaultMetadata` (Pydantic v2):

```python
class VaultEntry(BaseModel):
    id: UUID
    title: str
    username: str | None = None
    secret: str
    notes: str | None = None
    tags: list[str] = []
    created_at: datetime
    updated_at: datetime

class VaultMetadata(BaseModel):
    schema_version: int = 1
    entries: list[VaultEntry]
```

---

## 6. KDF and encryption — parameters

```python
class KDFConfig(BaseModel):
    time_cost: int = 3              # allowed read-time range: 2..10
    memory_cost_kib: int = 65536    # 64 MiB; allowed range: 19456..262144 (19..256 MiB)
    parallelism: int = 4            # allowed range: 1..8
    hash_len: int = 32              # protocol constant, -> 256-bit key for AES-256
    salt_len: int = 16
```

Defaults are the OWASP Password Storage Cheat Sheet starting point for
Argon2id, configurable at `vault init --time-cost N --memory-cost N
--parallelism N` (all three flags, not just the first two — `[grill-me v3,
Claude Code F20: in v2 `--parallelism` was configurable in the file but had
no CLI flag]`).

**Upper bound lowered from 1 GiB to 256 MiB** `[grill-me v3, OpenCode
V2-NEW-6]`: 1 GiB is technically within range, but a legitimate
(non-adversarial) call with `memory_cost=1 GiB` kills the process on a CI
runner or a container with a 512 MiB limit exactly like an attack does —
`OOM killer` with no structured error, just death. 256 MiB is a generous
Argon2id budget (well above the OWASP minimum) and safe on typical
constrained environments.

**The upper bound is mandatory** `[grill-me v2, CRYPTO-2, HIGH]`: the file
format stores `memory_cost_kib` as `uint32`, allowing values up to ~4 GiB.
An attacker with write access to the file can plant extreme KDF parameters —
the victim unlocking the vault gets OOM/kill instead of a usable error.
`storage.py` **must** validate parameter ranges when reading the header
**before** calling Argon2id, and reject the file with a clear error if
values fall outside the ranges above.

**Master-password verification** — NOT via a separate password hash. The only
check is attempting the AES-GCM decrypt and verifying the tag.

### Error classification when opening a vault `[grill-me v2, refinement]`

We distinguish two classes, not one:

1. **Structural errors** (bad magic, unknown `version`, file shorter than 49
   bytes, KDF parameters outside allowed ranges) — detected **before**
   decryption attempts and reveal nothing about the password. They can and
   should be reported precisely ("unsupported vault format" / "corrupted
   header"), **but not down to the specific violated byte/field** `[grill-me
   v3, OpenCode V2-NEW-5]`: distinguishing "bad magic" from "bad kdf_type"
   gives an offline password guesser nothing (they already hold the file with
   all header parameters), but detailed errors can help an attacker
   **preparing** a malformed vault to attack a victim's CLI distinguish fake
   headers from real ones without touching the CLI itself. One message for
   the whole structural class: "vault file is invalid or unsupported".
2. **Crypto errors** (bad GCM tag after successful header parsing) — here a
   single message `"Decryption failed: wrong password or corrupted vault"`
   and a **single exit code** for both cases (wrong password vs corrupted
   ciphertext) — otherwise differing exit codes themselves become an oracle,
   scriptable even when the message text matches.

### Minimal master-password check `[grill-me v2, TM-3, HIGH; refined v3]`

The entire "computationally infeasible" claim in §2 rests on brute force
being expensive due to Argon2id — true only against random or sufficiently
entropic passwords. At `vault init` and `change-master-password` a basic
strength check runs (minimum length ≥ 12 characters + checking against a
**built-in static list** of the most common leaked passwords — **no network
requests** `[grill-me v3, Claude Code F20: removes the contradiction with
§1's "no network stack" scope — the v2 wording was ambiguous enough to be
read as HIBP-style live lookup]`; the list is a few thousand entries baked
into the package, no zxcvbn). The check does **not** hard-block
(`--i-know-its-weak` for explicit confirmation).

**The same check applies to the export password** at `vault export`
`[grill-me v3, Claude Code F20]` — it protects the same secrets offline as
the master password, and was skipped by this policy in v2 without
justification.

---

## 7. Session model: **stateless**

Every CLI invocation requiring secret access (`get`, `add`, `list`,
`export`, ...) asks for the master password anew via `getpass` (not echoed,
never lands in shell history).

**Why not a daemon/unlock-session with TTL:** it is the safest default — the
key lives in process memory exactly for the duration of one operation, not
potentially for hours inside a background daemon. For a portfolio project it
is also architecturally simpler and avoids extra attack surface (daemon unix
socket, PID file, races under concurrent invocations).

Explicitly noted as a *possible future extension*, not v1: `vault unlock
--timeout 300` with the key cached in a separate background process. If
wanted, discuss separately — it is a distinct architectural surface with its
own threat model.

---

## 8. CLI commands (Typer)

```
vault init                          # create a new vault, set the master password
vault add <title>                   # add an entry (interactive prompt for the secret)
vault get <title>                   # show / copy to clipboard
vault list [--tag TAG]              # list entries (without secrets)
vault update <title>                # modify an entry
vault delete <title>                # remove an entry
vault generate [--length N]         # generate a password (no unlock required)
vault change-master-password        # re-encrypt with a new password, new salt
vault export --out FILE             # encrypted export (separate password mandatory)
vault import --in FILE              # import from an encrypted export
vault status                        # revision, entry count, .bak path
```

### `generate` — cryptographically strong generator

`generator.py` uses the `secrets` module (not `random`). Configurable:
length, character sets, minimum digits/specials. Requires no vault unlock —
a pure function without side effects.

### `get` — clipboard with auto-clear via a detached helper process

`[grill-me v2, CRITICAL from both independent agents]` v1 assumed a
`threading.Timer` inside the `vault get` process — architecturally broken:
the CLI exits right after output (normal UX for a one-shot command), the
timer thread dies with the parent, and the buffer physically never gets
cleared. Waiting on the timer in foreground (non-daemon) would block the
command for 20 seconds — unacceptable UX for a CLI tool.

**Solution:** `clipboard.py` copies the secret via `pyperclip` and starts a
**separate detached process**, `clipboard_clearer.py`, which sleeps for the
configured time, then clears the buffer **only if it still contains exactly
this secret** (compared via `hmac.compare_digest`, not `==` — the same
constant-time comparison discipline as for GCM tags in §12 `[grill-me v3,
OpenCode V2-NEW-4]`).

The secret hash is passed to the helper **via a temporary file created with
`tempfile.mkstemp()`**, whose path is passed as an argument, **not the hash
itself via `--hash`** `[grill-me v3, OpenCode V2-NEW-4, the significant find
of round two]`: process arguments are visible in `ps aux` to **all local
users** for the timer's entire lifetime (default 20 seconds) — a secret hash
in `argv` becomes an offline dictionary oracle available to anyone who can
run `ps` while the timer lives, even unsalted. The temp file is created with
`0600` on POSIX; on Windows `0600` is a no-op (see §2 — no ACL set)
`[grill-me v4, follow-up to V2-NEW-4]` — hence the file lives for the
minimal window and is deleted by the helper immediately after reading, in a
`finally`; on Windows additionally best-effort `SetFileInformationByHandle` /
ACL via `win32security` if available, else documented as a known limitation
(the hash in the file is readable by any local user who reads it by path
from `argv` within ~20 s).

File lifecycle `[grill-me v4]`: parent `mkstemp → write(hash) →
os.fchmod(0o600) → close(fd) → Popen →`, helper `read → unlink` in its
`finally`. If `Popen` throws or is unavailable — **the parent deletes the
file itself in its own `finally`** (otherwise the hash stays on disk
indefinitely) and degrades gracefully: a stderr warning that autoclear will
not run, without failing the main command. The file path is still visible in
the helper's `argv` (`--hash-file <path>`), but that is not an offline
oracle: the path is random (`mkstemp` + `O_EXCL`), and without reading the
file at that path the attacker gains nothing; reading is protected by `0600`
on POSIX.

Launch: `subprocess.Popen([sys.executable, "-m",
"secure_secrets_vault.clipboard_clearer", "--hash-file", tmp_path, "--delay",
"20"], start_new_session=True)` on POSIX; on Windows
`creationflags=subprocess.DETACHED_PROCESS |
subprocess.CREATE_NEW_PROCESS_GROUP` instead of `start_new_session`, which
only acts on POSIX and would be a no-op on Windows `[grill-me v3, both
agents flagged the Windows specifics separately]`.

On Linux, `pyperclip` requires system `xclip` or `xsel` — document as a
runtime dependency in README (`[grill-me v2, portability]`).

A `--print` flag is also available for explicit stdout output instead of the
clipboard (for scripting, at your own risk — no autoclear).

---

## 9. Multi-vault

The file path is not hardcoded: `--vault-path` (default
`~/.secure_vault/vault.enc`, also configurable via the `SSV_VAULT_PATH` env
var). Multiple profiles are simply different paths, with no separate
"profile" concept in code: fewer entities, same flexibility.

---

## 10. Export / Import

- Export is **always** re-encrypted with a **new** `salt` and `nonce`
  `[grill-me v2, EXP-3: explicitly, regardless of whether the export password
  matches the main one — otherwise the export key equals the working vault
  key]`, with a separate password (same or different, e.g. for handing to a
  third party; double prompt on input). Format identical to the main vault
  file except magic bytes: `b"SSVE"` — export, to avoid accidentally
  confusing it with the working vault. `revision_counter` starts at 0 in the
  export (it is a new, independent file, not a continuation of the working
  vault's history). Export writing goes through the same atomic-write path
  (§5), including `fsync` — an interrupted export must not leave a partially
  written file.

- **Import — merge semantics** `[grill-me v2, was CRITICAL from Claude Code]`:
  - Import by default requires an initialized vault; the `--init-if-missing`
    flag allows creating a new vault right inside the import (prompting for a
    new master password) when `vault.enc` is absent — otherwise recovery
    after file loss requires a separate `init` → `import` dance that is easy
    to forget in a stressful recovery situation `[grill-me v3, OpenCode
    V2-NEW-8]`.
  - On `id` (UUID) collision — the record is skipped and the CLI prints a
    warning listing skipped `id`s. UUIDs are unique by construction, so a
    collision almost always means "this entry was already imported" — silent
    overwrite would allow quietly clobbering an existing secret with data
    from an untrusted export.
  - On `title` collision (different `id`s, same `title`) — the record **is
    imported anyway** (title is not a unique key), but the CLI prints an
    ambiguity warning for later `vault get <title>` (see §13, "duplicate
    titles" — resolved to the latest added; the user can rename manually).
  - Flag `--overwrite-conflicts` (renamed from `--force` in v2 — see below
    on the flag-name collision) switches "skip on id collision" to
    "overwrite" — explicit only, never default.
  - **`revision_counter` increments even if every record was skipped**
    (an import with zero data effect) `[grill-me v3, OpenCode V2-NEW-8]` — a
    deliberate compromise: the invariant is "revision == number of file-write
    operations", not "revision == number of actual data changes". The strict
    second invariant would require cancelling the whole file write on a no-op
    import, complicating the atomic-write path with no real benefit —
    documented, not considered a bug.

- Plaintext export is NOT a default path. Available only via the explicit
  `--unsafe-plaintext-json FILE` flag — the channel is fixed as a **file**,
  not stdout (stdout lands uncontrollably in shell scrollback/CI logs; a
  file can at least be chmod'd `0600` and deliberately deleted). On an
  interactive terminal (`isatty() == True`) it requires a `y/N` confirmation.
  **On the non-interactive path (pipe/CI) both factors are required
  simultaneously: the `--yes-i-understand` flag AND the literal `y` read from
  stdin** — not one instead of the other `[grill-me v3, OpenCode V2-NEW-7,
  significant find: the flag name `--force` was shared between import
  (=overwrite) and export (=non-tty bypass); implementing "non-tty → --force"
  instead of "non-tty → --force AND y" made `echo y | vault export
  --unsafe... --force` a documented bypass of the interactive confirmation —
  exactly what the confirmation existed to prevent]`. The flag was renamed to
  `--yes-i-understand` so it no longer shares a name with import's
  `--overwrite-conflicts` — different consequences must not hide behind a
  single `--force` token.

  After writing — a stderr warning with the exact file path and a reminder
  to delete after use. JSON has no MAC — modification before re-`import` is
  undetectable; accepted compromise for unsafe mode, documented.
  **Plaintext import (the reverse operation — reading unsafe exports back
  into a vault) is out of scope for v1** `[grill-me v3, Claude Code F21: v2
  text referenced "re-importing" a plaintext file although such a command
  does not exist — `vault import` only accepts the encrypted `SSVE` format;
  if plaintext-import ever appears, it becomes precisely the merge-bypass
  vector described above for `--overwrite-conflicts` and must get its own
  grill-me round rather than inherit this specification by default]`.

---

## 11. Error handling and logging

- **Secrets/passwords never appear in exceptions, tracebacks, or logs.**
  Custom exception classes (`exceptions.py`) separate the structural class
  (`CorruptedVaultError`, `UnsupportedFormatError`) from the crypto class
  (`AuthenticationFailedError` — single message and single exit code, see
  §6) and never carry field values like secrets or passwords.
- Operation logging ("vault unlocked", "entry added") — at operation level;
  whether `<title>` appears in logs is a deliberate decision, not a default:
  title is vault-structure metadata; in strict mode log only `id`
  `[grill-me v2, F14]`.
- **`<title>` as a positional CLI argument** (`vault get <title>`) is visible
  in `ps aux`, shell history, `auditd` for the duration of the command
  `[grill-me v2, SESS-4, known limitation, LOW]`. Document in `--help`; the
  alternative (interactive title prompt instead of argv) is rejected for v1 —
  it hurts scriptability more than the risk justifies for a local
  single-user CLI.
- Duplicate `title`s on `add`: not forbidden (title is not a unique key, `id`
  is), but `get`/`update`/`delete <title>` with multiple matches resolve to
  the latest added entry with an explicit ambiguity warning in the CLI
  `[grill-me v2, F13]`.
- `mypy --strict` is mandatory, as in the other projects; `Pydantic v2` for
  all schemas.

---

## 12. Testing

Project standard: real `pytest -v`, no fabricated output. In addition to
regular unit/integration tests — a crypto-specific checklist:

- Nonces **never** repeat between encryption calls (property-test with a
  deterministic mock of `os.urandom`, not raw random — otherwise the test
  flakes `[grill-me v2, refinement]`)
- Changing any byte of ciphertext or AAD `[0:37)` → `decrypt` raises, returns
  no garbage data (see §5, exact AAD definition)
- Constant-time tag comparison behavior — delegated to `cryptography` (the
  library provides the guarantee); tests verify we added no own `==` over
  secret bytes anywhere in the code
- Wrong-password path and corrupted-ciphertext path produce **identical**
  messages **and identical exit codes** (regression against oracle leakage;
  structural errors are a separate class, see §6)
- `vault.enc.tmp` does not remain on disk after a successful operation
- **`fsync` is called** before `os.replace` (mocked at the test level — we
  verify the call happened, not actual power-loss) `[grill-me v2]`
- **File lock** blocks a second concurrent `add`/`update`/`delete` until the
  first completes — a two-concurrent-invocations test, no lost updates
  `[grill-me v2]`
- **Sidecar `.rev` updated strictly after `os.replace`** under the same lock
  as the vault write — two parallel `add`s must end at `revision_counter ==
  2` (not `1` from the race) `[grill-me v3]`
- **Lock timeout** yields `VaultBusyError`, not a raw exception, when the
  lock stays busy past the configured limit `[grill-me v3]`
- KDF parameters outside **19456..262144 KiB** (updated upper bound) at
  header-read time → `UnsupportedFormatError` before Argon2id runs, not OOM
  `[grill-me v3: range narrowed]`
- `revision_counter` decreased between runs (checked against `.rev`) →
  possible-rollback warning whose text states explicitly that the mechanism
  does not protect against full-directory rollback `[grill-me v3]`
- **Reader and writer close the file handle before `decrypt`** — mock test
  verifies the call order `read()` → `close()` → `Argon2id` on both paths,
  before, not after, the cryptographic operation `[grill-me v4: extends the
  v3 Windows regression to writers]`
- **Lock released in `finally` on early-return/exception** — test injects an
  error between steps 3 and 5 and verifies the second `add` does not get a
  permanent `VaultBusyError` `[grill-me v4, follow-up to V2-NEW-1]`
- **Corrupted `.rev` → `0` with warning, not fatal** — writes succeed with
  garbage in `.rev` `[grill-me v4]`
- **Clipboard clearer receives the hash via a file, not `argv`** — test
  verifies `secret_hash` does not appear in the launched `subprocess.Popen`
  argument list `[grill-me v3, OpenCode V2-NEW-4]`
- **Parent deletes the tempfile on `Popen` failure** — mocked `Popen`
  `side_effect` → `tmp_path` does not remain on disk `[grill-me v4,
  follow-up to V2-NEW-4]`

A fourth `grill-me` round (after the v4 patch) is the final verification of
the v4 delta (finally for the lock, corrupted `.rev`, writer-handle,
tempfile-cleanup) before starting `crypto.py`. Round three (v3) closed
V2-NEW-1/V2-NEW-4 and the `--force` split; v4 closes residual spec
incompleteness inside already-fixed zones.

---

## 13. Implementation order

1. `models.py` — Pydantic schemas (no crypto, no I/O)
2. `crypto.py` — KDF + AEAD encrypt/decrypt, tested in isolation
3. `storage.py` — binary format, atomic write, over `crypto.py`
4. `vault.py` — orchestration (`VaultManager`)
5. `generator.py`, `clipboard.py` — standalone utility modules
6. `cli.py` — Typer shell over everything

`code-review` is mandatory after each module, as in the previous projects,
with extra focus on modules 2–4.

---

## 14. Implementation status and deliberate deviations

v1 is implemented (all modules from §13, 88 tests passing, `mypy --strict`
clean). A post-implementation code review of modules 2–4 surfaced findings
that changed the spec below in minor ways. Recorded here so the document
stays honest about where code and text differ:

1. **Decrypt runs inside the lock** (`vault.py` `_transform`). The first
   implementation decrypted outside `update_vault`'s critical section and
   rebuilt from that stale snapshot — two parallel `add`s would both decrypt
   old state and the second silently clobbered the first (lost update with a
   *correct* revision). Read → parse → KDF → decrypt now happen inside
   `transform`, i.e. under the lock. §5's "single atomic section" is now
   literally true.
2. **Import collision decisions are made inside the critical section too**
   (previously `existing_ids` was snapshotted before the lock). Skipped-id
   and ambiguous-title lists are filled by the transform running under the
   lock; no extra KDF run for the final title recount.
3. **`initialize` checks existence inside the critical section.** An
   `exists()` pre-check remains for a friendly fast-fail, but the authoritative
   check happens under the lock against `ctx.current_raw` — closing a
   check-then-act race between two concurrent `init`s.
4. **Export writes via plain atomic write, not the full vault cycle**
   (deviation from §10's "same atomic-write path"). Running export through
   `update_vault` produced `.rev`/`.lock`/`.bak` litter next to the export
   and created a stale-password `.bak`. Export now does tmp+fsync+replace
   directly: it is a new independent file (§10 already says so) with nothing
   to roll back. It also refuses to target the live vault path.
5. **`change-master-password` inherits KDF parameters from the current
   header** instead of resetting to defaults — otherwise a user who chose
   `--time-cost/--memory-cost/--parallelism` at init gets them silently
   reverted by a password change.
6. **`update_entry`/`delete_entry` raise `EntryNotFoundError` on a missing
   id** instead of performing a silent no-op data change that still bumps
   revision. Consistent with `resolve_title` semantics; also means a failed
   mutation does not produce a file write.
7. **Rollback warning implemented at write time**: if the current header
   revision is older than the sidecar revision, every writer emits a stderr
   warning stating explicitly that full-directory rollback is not covered
   (closes the last open item of the §12 checklist).
8. **Honest gap vs §6:** the built-in leaked-password list currently holds
   ~100 entries, not the aspirational "few thousand". The structure accepts a
   larger dataset without API changes; treat the small list as best-effort
   until swapped.
9. **Honest gap vs §7:** import performs up to three Argon2id runs per
   invocation (import-file decrypt + own-vault transform), not strictly one.
   Correctness (decrypt-inside-lock, see item 1) was preferred over the
   single-KDF ideal; the extra cost is bounded and only on the import path.

---

*v4 — delta fix following verification of v3 (Claude Code + OpenCode/Muse
Spark 1.2): completed `finally` for the lock, corrupted `.rev` handling,
writer-handle-before-decrypt, Windows-ACL/cleanup for the clipboard hash
tempfile. V2-NEW-1/V2-NEW-4 and the `--force` split confirmed closed.*

*v5 — v1 implementation completed and reviewed; deviations recorded in §14.*
