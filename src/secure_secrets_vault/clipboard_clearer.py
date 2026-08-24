"""Detached helper: очистка буфера по таймеру.

Запускается как `python -m secure_secrets_vault.clipboard_clearer
--hash-file PATH --delay N`. Хэш читается из файла (не argv, §8), файл
удаляется в finally. Буфер очищается только если он всё ещё содержит
именно этот секрет (hmac.compare_digest).
"""

import argparse
import hashlib
import hmac
import os
import sys
import time


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="clipboard auto-clear helper")
    parser.add_argument("--hash-file", required=True)
    parser.add_argument("--delay", type=int, default=20)
    args = parser.parse_args(argv)

    try:
        with open(args.hash_file, encoding="ascii") as f:
            expected_hash = f.read().strip()
    except OSError:
        return 1

    current: str | None = None
    try:
        import pyperclip

        time.sleep(max(0, args.delay))
        pasted = pyperclip.paste()
        if isinstance(pasted, str):
            current = pasted
    except Exception:  # noqa: BLE001 — helper не должен шуметь при деградации
        current = None
    finally:
        try:
            os.unlink(args.hash_file)
        except OSError:
            pass

    if current is not None and hmac.compare_digest(
        hashlib.sha256(current.encode("utf-8")).hexdigest(), expected_hash
    ):
        try:
            import pyperclip

            pyperclip.copy("")
        except Exception:  # noqa: BLE001
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
