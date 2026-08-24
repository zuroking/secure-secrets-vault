"""Пути по умолчанию, KDF-параметры, протокольные константы."""

from pathlib import Path

DEFAULT_VAULT_FILENAME = "vault.enc"

HEADER_MAGIC = b"SSV\x00"
EXPORT_MAGIC = b"SSVE"
FORMAT_VERSION = 1
KDF_TYPE_ARGON2ID = 0x01

SALT_LEN = 16
NONCE_LEN = 12
HASH_LEN = 32
KEY_LEN = 32

HEADER_LEN = 49  # magic(4)+version(1)+kdf_type(1)+salt(16)+time(1)+mem(4)+par(1)+hash_len(1)+revision(8)+nonce(12)
AAD_LEN = 37  # AAD = header[0:37) — до nonce; nonce [37:49) в AAD не входит

REVISION_MIN = 0
REVISION_MAX = 2**64 - 1

LOCK_TIMEOUT_SECONDS = 10.0
LOCK_RETRY_ATTEMPTS = 3
CLIPBOARD_CLEAR_DELAY_SECONDS = 20
MIN_PASSWORD_LENGTH = 12

KDF_TIME_COST_RANGE: tuple[int, int] = (2, 10)
KDF_MEMORY_COST_KIB_RANGE: tuple[int, int] = (19456, 262144)
KDF_PARALLELISM_RANGE: tuple[int, int] = (1, 8)


def default_vault_path() -> Path:
    import os

    env = os.environ.get("SSV_VAULT_PATH")
    if env:
        return Path(env)
    return Path.home() / ".secure_vault" / DEFAULT_VAULT_FILENAME
