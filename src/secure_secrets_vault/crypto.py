"""KDF (Argon2id) и AEAD (AES-256-GCM) поверх аудированных библиотек.

Модуль не знает о storage.py: AAD передаётся готовыми raw-байтами.
"""

import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config
from .config import KDF_TIME_COST_RANGE, KDF_MEMORY_COST_KIB_RANGE, KDF_PARALLELISM_RANGE
from .exceptions import AuthenticationFailedError, UnsupportedFormatError
from .models import KDFConfig


def validate_kdf_params(kdf: KDFConfig) -> None:
    """Валидация диапазонов при чтении заголовка — до вызова Argon2id.

    Иначе атакующий подставляет экстремальные параметры → OOM вместо
    структурной ошибки (ARCHITECTURE.md §6).
    """
    lo, hi = KDF_TIME_COST_RANGE
    if not lo <= kdf.time_cost <= hi:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)
    lo, hi = KDF_MEMORY_COST_KIB_RANGE
    if not lo <= kdf.memory_cost_kib <= hi:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)
    lo, hi = KDF_PARALLELISM_RANGE
    if not lo <= kdf.parallelism <= hi:
        raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)


def derive_key(password: str, salt: bytes, kdf: KDFConfig) -> bytes:
    """Argon2id: один прогон за вызов CLI, ключ для всех операций вызова."""
    validate_kdf_params(kdf)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=kdf.time_cost,
        memory_cost=kdf.memory_cost_kib,
        parallelism=kdf.parallelism,
        hash_len=config.KEY_LEN,
        type=Type.ID,
    )


def new_nonce() -> bytes:
    """Свежий nonce на каждый вызов encrypt — единственная защита от re-use."""
    return os.urandom(config.NONCE_LEN)


def encrypt(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes) -> bytes:
    """AES-256-GCM; aad — raw-байты заголовка [0:37), один буфер с диском."""
    if len(key) != config.KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != config.NONCE_LEN:
        raise ValueError("nonce must be 12 bytes")
    return AESGCM(key).encrypt(nonce, plaintext, aad or None)


def decrypt(key: bytes, ciphertext_with_tag: bytes, nonce: bytes, aad: bytes) -> bytes:
    """Единая крипто-ошибка на неверный тег: wrong password == corrupted."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext_with_tag, aad or None)
    except InvalidTag as exc:
        raise AuthenticationFailedError(AuthenticationFailedError.MESSAGE) from exc
