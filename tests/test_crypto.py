import os
from collections.abc import Callable
from unittest import mock

import pytest

from secure_secrets_vault import crypto
from secure_secrets_vault.exceptions import (
    AuthenticationFailedError,
    UnsupportedFormatError,
)
from secure_secrets_vault.models import KDFConfig

PASSWORD = "correct horse battery staple"
LOW_KDF = KDFConfig(time_cost=2, memory_cost_kib=19456, parallelism=1)


def make_key() -> bytes:
    return crypto.derive_key(PASSWORD, os.urandom(16), LOW_KDF)


def make_aad() -> bytes:
    return os.urandom(37)


class TestDeriveKey:
    def test_key_length(self) -> None:
        assert len(make_key()) == 32

    def test_deterministic_same_inputs(self) -> None:
        salt = os.urandom(16)
        assert crypto.derive_key(PASSWORD, salt, LOW_KDF) == crypto.derive_key(
            PASSWORD, salt, LOW_KDF
        )

    def test_different_salt_different_key(self) -> None:
        assert crypto.derive_key(PASSWORD, b"\x00" * 16, LOW_KDF) != crypto.derive_key(
            PASSWORD, b"\x01" * 16, LOW_KDF
        )

    @pytest.mark.parametrize(
        "field,bad",
        [("time_cost", 1), ("time_cost", 11), ("memory_cost_kib", 19455),
         ("memory_cost_kib", 262145), ("parallelism", 0), ("parallelism", 9)],
    )
    def test_out_of_range_rejected_before_kdf(self, field: str, bad: int) -> None:
        base: dict[str, int] = {"time_cost": 2, "memory_cost_kib": 19456, "parallelism": 1}
        base[field] = bad
        kdf = KDFConfig(**base)
        with mock.patch("secure_secrets_vault.crypto.hash_secret_raw") as m:
            with pytest.raises(UnsupportedFormatError):
                crypto.derive_key(PASSWORD, b"\x00" * 16, kdf)
        m.assert_not_called()


class TestEncryptDecryptRoundtrip:
    def test_roundtrip(self) -> None:
        key = make_key()
        aad = make_aad()
        nonce = crypto.new_nonce()
        ct = crypto.encrypt(key, b"secret-data", nonce, aad)
        assert crypto.decrypt(key, ct, nonce, aad) == b"secret-data"


class TestAadBitFlips:
    """Flip любого байта в AAD [0:37) → decrypt кидает исключение."""

    def test_every_byte_in_aad(self) -> None:
        key = make_key()
        base = bytearray(make_aad())
        ct = crypto.encrypt(key, b"x", crypto.new_nonce(), bytes(base))
        for i in range(37):
            flipped = bytearray(base)
            flipped[i] ^= 0x01
            with pytest.raises(AuthenticationFailedError):
                crypto.decrypt(key, ct, crypto.new_nonce(), bytes(flipped))


class TestNonceBitFlip:
    """Flip байта nonce [37:49)-эквивалент — тоже исключение (регрессия F25)."""

    def test_flipped_nonce_rejected(self) -> None:
        key = make_key()
        aad = make_aad()
        nonce = crypto.new_nonce()
        ct = crypto.encrypt(key, b"x", nonce, aad)
        bad_nonce = bytes([nonce[0] ^ 0x01]) + nonce[1:]
        with pytest.raises(AuthenticationFailedError):
            crypto.decrypt(key, ct, bad_nonce, aad)


class TestCiphertextTamper:
    def test_ciphertext_flip_rejected(self) -> None:
        key = make_key()
        aad = make_aad()
        ct = bytearray(crypto.encrypt(key, b"secret", crypto.new_nonce(), aad))
        ct[0] ^= 0x01
        with pytest.raises(AuthenticationFailedError):
            crypto.decrypt(key, ct, crypto.new_nonce(), aad)


class TestWrongPasswordOracle:
    """Wrong password и corrupted ciphertext — одно сообщение и один класс."""

    def test_identical_message_both_paths(self) -> None:
        key = make_key()
        aad = make_aad()
        nonce = crypto.new_nonce()
        ct = crypto.encrypt(key, b"x", nonce, aad)

        other_key = crypto.derive_key("wrong password", b"\x00" * 16, LOW_KDF)

        caught: list[str] = []
        for bad_key in (other_key,):
            try:
                crypto.decrypt(bad_key, ct, nonce, aad)
            except AuthenticationFailedError as e:
                caught.append(str(e))
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF
        try:
            crypto.decrypt(key, bytes(tampered), nonce, aad)
        except AuthenticationFailedError as e:
            caught.append(str(e))

        assert len(caught) == 2
        assert caught[0] == caught[1]
        assert isinstance(caught[0], str)


class TestNonceFreshness:
    """Nonce никогда не повторяется — детерминированный mock os.urandom."""

    def test_no_repeat_over_many_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counter = {"n": 0}

        def fake_urandom(size: int) -> bytes:
            value = counter["n"].to_bytes(size, "big")
            counter["n"] += 1
            return value

        total = 500
        monkeypatch.setattr(os, "urandom", fake_urandom)
        nonces = [crypto.new_nonce() for _ in range(total)]
        assert len(set(nonces)) == len(nonces) == total

    def test_real_nonces_unique_and_random_len(self) -> None:
        nonces = {crypto.new_nonce() for _ in range(200)}
        assert len(nonces) == 200
        assert all(len(n) == 12 for n in nonces)


class TestInputValidation:
    def test_bad_key_length(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            crypto.encrypt(b"short", b"x", crypto.new_nonce(), make_aad())

    def test_bad_nonce_length(self) -> None:
        with pytest.raises(ValueError, match="12 bytes"):
            crypto.encrypt(b"\x00" * 32, b"x", b"\x00" * 8, make_aad())


def test_decrypt_accepts_empty_aad_equivalent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AAD=None и b"" эквивалентны для AESGCM; проверяем отсутствие сюрпризов."""
    key = make_key()
    nonce = crypto.new_nonce()

    def enc(aad: bytes | None) -> Callable[[bytes], bytes]:
        payload = crypto.encrypt(key, b"data", nonce, aad or b"")
        return lambda a: crypto.decrypt(key, payload, nonce, a or b"")

    dec = enc(b"")
    assert dec(b"") == b"data"
    assert dec(None) == b"data"
