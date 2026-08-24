"""Бинарный формат vault-файла, atomic write, file lock, sidecar .rev.

Модуль не знает о crypto.py: он оперирует готовыми raw-байтами файла
(заголовок + ciphertext). AAD-семантику обеспечивает вызывающий
(vault.py), передавая тот же буфер заголовка, что пишется на диск.
"""

import contextlib
import errno
import os
import shutil
import struct
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from . import config
from .exceptions import UnsupportedFormatError, VaultBusyError
from .models import KDFConfig

_LOCK_POLL_INTERVAL = 0.05


@dataclass(frozen=True)
class VaultHeader:
    magic: bytes
    version: int
    kdf_type: int
    salt: bytes
    time_cost: int
    memory_cost_kib: int
    parallelism: int
    hash_len: int
    revision: int
    nonce: bytes


def serialize_header(header: VaultHeader) -> bytes:
    """Один буфер: пишется на диск как заголовок и служит источником AAD."""
    if len(header.salt) != config.SALT_LEN:
        raise ValueError("salt must be 16 bytes")
    if len(header.nonce) != config.NONCE_LEN:
        raise ValueError("nonce must be 12 bytes")
    return b"".join(
        [
            header.magic,
            struct.pack(">B", header.version),
            struct.pack(">B", header.kdf_type),
            header.salt,
            struct.pack(">B", header.time_cost),
            struct.pack(">I", header.memory_cost_kib),
            struct.pack(">B", header.parallelism),
            struct.pack(">B", header.hash_len),
            struct.pack(">Q", header.revision),
            header.nonce,
        ]
    )


def parse_header(
    raw: bytes, magic: bytes = config.HEADER_MAGIC
) -> tuple[VaultHeader, bytes]:
    """Строгий порядок валидации: magic → version → kdf_type → KDF-диапазоны.

    Единое сообщение на весь структурный класс; magic проверяется целиком.
    Для экспортного файла передаётся magic=b"SSVE".
    Возвращает (header, ciphertext_with_tag).
    """
    if len(raw) < config.HEADER_LEN or raw[:4] != magic:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)
    version = raw[4]
    if version != config.FORMAT_VERSION:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)
    kdf_type = raw[5]
    if kdf_type != config.KDF_TYPE_ARGON2ID:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)
    salt = raw[6:22]
    time_cost = raw[22]
    (memory_cost_kib,) = struct.unpack(">I", raw[23:27])
    parallelism = raw[27]
    hash_len = raw[28]
    (revision,) = struct.unpack(">Q", raw[29:37])
    nonce = raw[37:49]

    lo, hi = config.KDF_TIME_COST_RANGE
    if not lo <= time_cost <= hi:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)
    lo, hi = config.KDF_MEMORY_COST_KIB_RANGE
    if not lo <= memory_cost_kib <= hi:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)
    lo, hi = config.KDF_PARALLELISM_RANGE
    if not lo <= parallelism <= hi:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)
    if hash_len != config.HASH_LEN or len(salt) != config.SALT_LEN:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)

    header = VaultHeader(
        magic=raw[:4],
        version=version,
        kdf_type=kdf_type,
        salt=salt,
        time_cost=time_cost,
        memory_cost_kib=memory_cost_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        revision=revision,
        nonce=nonce,
    )
    return header, raw[config.HEADER_LEN :]


def header_to_kdf_config(header: VaultHeader) -> KDFConfig:
    return KDFConfig(
        time_cost=header.time_cost,
        memory_cost_kib=header.memory_cost_kib,
        parallelism=header.parallelism,
        hash_len=header.hash_len,
        salt_len=config.SALT_LEN,
    )


def read_file_closed(path: Path) -> bytes | None:
    """Прочитать файл целиком и закрыть handle ДО крипто-операции.

    На Windows открытый handle блокирует os.replace параллельного писателя.
    """
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def sidecar_path(vault_path: Path) -> Path:
    """Per-vault sidecar: <vault_path>.rev."""
    return vault_path.with_name(vault_path.name + ".rev")


def lock_path(vault_path: Path) -> Path:
    return vault_path.with_name(vault_path.name + ".lock")


@contextlib.contextmanager
def file_lock(vault_path: Path, timeout: float = config.LOCK_TIMEOUT_SECONDS) -> Iterator[None]:
    """Advisory exclusive lock с таймаутом; весь write-cycle под одним lock'ом."""
    lp = lock_path(vault_path)
    fd = os.open(lp, os.O_CREAT | os.O_RDWR)
    deadline = time.monotonic() + timeout
    acquired = False
    try:
        while True:
            try:
                _try_lock(fd)
                acquired = True
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                if time.monotonic() >= deadline:
                    raise VaultBusyError("another operation in progress") from exc
                time.sleep(_LOCK_POLL_INTERVAL)
        yield
    finally:
        if acquired:
            with contextlib.suppress(OSError):
                _release_lock(fd)
        os.close(fd)


def _try_lock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        flock = getattr(fcntl, "flock")
        lock_ex = getattr(fcntl, "LOCK_EX")
        lock_nb = getattr(fcntl, "LOCK_NB")
        flock(fd, lock_ex | lock_nb)


def _release_lock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        getattr(fcntl, "flock")(fd, getattr(fcntl, "LOCK_UN"))


def read_revision(vault_path: Path) -> int:
    """.rev отсутствует → 0; битый (не ASCII-десятичное число) → 0 + warning.

    Коррапт sidecar никогда не блокирует запись — иначе DoS подкладыванием
    мусора в <vault_path>.rev (ARCHITECTURE.md §5 v4).
    """
    sp = sidecar_path(vault_path)
    try:
        data = sp.read_bytes()
    except FileNotFoundError:
        return 0
    text = data.decode("ascii", errors="strict").strip()
    try:
        value = int(text, 10)
    except (ValueError, UnicodeDecodeError):
        print(
            f"warning: corrupted revision sidecar {sp}, treating as 0",
            file=sys.stderr,
        )
        return 0
    if not 0 <= value <= config.REVISION_MAX:
        print(
            f"warning: out-of-range revision in {sp}, treating as 0",
            file=sys.stderr,
        )
        return 0
    return value


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_file(target: Path, data: bytes) -> None:
    """tmp + fsync + os.replace — не оставлять частично записанный файл."""
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, target)
    with contextlib.suppress(OSError):
        _fsync_directory(target.parent)


@dataclass(frozen=True)
class WriteContext:
    current_raw: bytes | None
    revision_in: int


def update_vault(
    vault_path: Path,
    transform: Callable[[WriteContext], bytes],
    timeout: float = config.LOCK_TIMEOUT_SECONDS,
) -> int:
    """Единая критическая секция записи (ARCHITECTURE.md §5, шаги 1–10).

    transform получает текущее сырое содержимое (или None) и revision_in,
    возвращает полные новые байты файла (заголовок + ciphertext). Sidecar
    записывается строго после успешного os.replace основного файла. Lock
    освобождается в finally при любом исходе.
    """
    backup_path = vault_path.with_name(vault_path.name + ".bak")
    new_revision = -1
    with file_lock(vault_path, timeout):
        # Шаг 2–3: чтение в память, handle закрыт до крипто-операции.
        current_raw = read_file_closed(vault_path)
        revision_sidecar = read_revision(vault_path)
        revision_header = _header_revision(current_raw)
        if revision_header < revision_sidecar:
            # §12: vault.enc старее, чем .rev помнит, — возможный rollback.
            print(
                f"warning: possible rollback detected — vault revision "
                f"{revision_header} is older than sidecar revision "
                f"{revision_sidecar}. This mechanism does not protect "
                f"against full-directory rollback.",
                file=sys.stderr,
            )
        revision_in = max(revision_sidecar, revision_header)
        ctx = WriteContext(current_raw=current_raw, revision_in=revision_in)

        # Шаг 4: backup best-effort.
        if current_raw is not None:
            with contextlib.suppress(OSError):
                shutil.copyfile(vault_path, backup_path)

        payload = transform(ctx)

        # Шаги 5–8: tmp + fsync + replace + dir-fsync, с retry для Windows.
        _replace_with_retry(vault_path, payload)

        # Шаг 9: sidecar строго после успешного replace.
        # Revision читается по offset'у напрямую: payload только что собран
        # этим же процессом, а parse_header отклонил бы экспортный magic.
        new_revision = int(struct.unpack(">Q", payload[29:37])[0])
        atomic_write_file(sidecar_path(vault_path), str(new_revision).encode("ascii"))
    return new_revision


def _header_revision(raw: bytes | None) -> int:
    if raw is None:
        return 0
    try:
        header, _ = parse_header(raw)
    except UnsupportedFormatError:
        return 0
    return header.revision


def _replace_with_retry(
    target: Path,
    payload: bytes,
    attempts: int = config.LOCK_RETRY_ATTEMPTS,
) -> None:
    """os.replace с retry-with-backoff против PermissionError читателя (Windows)."""
    delay = 0.1
    for attempt in range(attempts):
        try:
            atomic_write_file(target, payload)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay *= 2
