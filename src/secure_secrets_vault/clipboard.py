"""Копирование в буфер с авто-очисткой через detached helper-процесс.

Хэш секрета передаётся helper'у через tempfile, не через argv
(ARCHITECTURE.md §8, OpenCode V2-NEW-4): путь в argv — не oracle,
рандомен mkstemp(O_EXCL), чтение защищено 0600 на POSIX.
"""

import contextlib
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .config import CLIPBOARD_CLEAR_DELAY_SECONDS
from .exceptions import ClipboardError


def secret_hash(secret: str) -> str:
    """SHA-256 секрета; сравнение в helper'е — hmac.compare_digest."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def copy_with_autoclear(secret: str, delay: int = CLIPBOARD_CLEAR_DELAY_SECONDS) -> bool:
    """Скопировать секрет и запустить clearer. False — autoclear недоступен."""
    try:
        import pyperclip

        pyperclip.copy(secret)
    except Exception as exc:  # noqa: BLE001 — pyperclip даёт разнородные ошибки
        raise ClipboardError(f"clipboard unavailable: {exc}") from exc

    fd, tmp_name = tempfile.mkstemp(prefix="ssv-hash-", suffix=".tmp")
    tmp_path = Path(tmp_name)
    spawned = False
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(secret_hash(secret))
        if os.name != "nt":
            with contextlib.suppress(OSError):
                os.chmod(tmp_path, 0o600)

        popen_kwargs: dict[str, Any]
        if os.name == "nt":
            popen_kwargs = {
                "creationflags": (
                    subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                )
            }
        else:
            popen_kwargs = {"start_new_session": True}

        try:
            subprocess.Popen(  # noqa: S603 — фиксированный argv, без shell
                [
                    sys.executable,
                    "-m",
                    "secure_secrets_vault.clipboard_clearer",
                    "--hash-file",
                    str(tmp_path),
                    "--delay",
                    str(delay),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **popen_kwargs,
            )
            # Успешный spawn: unlink делает helper после чтения (в его
            # finally). Родительский unlink здесь был бы гонкой с чтением.
            spawned = True
        except OSError:
            print(
                "warning: could not start clipboard clearer; "
                "the buffer will not be cleared automatically",
                file=sys.stderr,
            )
            return False
        return True
    finally:
        if not spawned:
            # Popen-fail: иначе tempfile с хэшем остаётся на диске (§8 v4).
            with contextlib.suppress(OSError):
                tmp_path.unlink()
