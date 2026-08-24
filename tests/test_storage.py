import os
import struct
import threading
from pathlib import Path
from unittest import mock

import pytest

from secure_secrets_vault import storage
from secure_secrets_vault.config import (
    EXPORT_MAGIC,
    HEADER_MAGIC,
    HEADER_LEN,
)
from secure_secrets_vault.exceptions import (
    UnsupportedFormatError,
    VaultBusyError,
)
from secure_secrets_vault.models import KDFConfig

LOW_KDF = KDFConfig(time_cost=2, memory_cost_kib=19456, parallelism=1)


def make_header_bytes(revision: int = 0) -> bytes:
    header = storage.VaultHeader(
        magic=HEADER_MAGIC,
        version=1,
        kdf_type=1,
        salt=b"\x01" * 16,
        time_cost=LOW_KDF.time_cost,
        memory_cost_kib=LOW_KDF.memory_cost_kib,
        parallelism=LOW_KDF.parallelism,
        hash_len=32,
        revision=revision,
        nonce=b"\x02" * 12,
    )
    return storage.serialize_header(header)


def make_payload(revision: int, body: bytes = b"ciphertext") -> bytes:
    return make_header_bytes(revision) + body


class TestHeaderRoundtrip:
    def test_serialize_parse_roundtrip(self) -> None:
        raw = make_header_bytes(revision=42)
        assert len(raw) == HEADER_LEN
        header, ciphertext = storage.parse_header(raw + b"tail")
        assert header.revision == 42
        assert header.salt == b"\x01" * 16
        assert header.nonce == b"\x02" * 12
        assert ciphertext == b"tail"

    def test_header_is_exactly_49_bytes(self) -> None:
        assert len(make_header_bytes()) == 49


class TestStructuralValidation:
    """Единое сообщение на весь структурный класс, строгий порядок шагов."""

    def assert_structural(self, raw: bytes) -> None:
        with pytest.raises(UnsupportedFormatError) as ei:
            storage.parse_header(raw)
        assert str(ei.value) == UnsupportedFormatError.MESSAGE

    def test_export_magic_rejected_as_not_a_vault(self) -> None:
        raw = bytearray(make_header_bytes())
        raw[:4] = EXPORT_MAGIC
        self.assert_structural(bytes(raw))

    def test_magic_checked_whole_not_prefix(self) -> None:
        raw = bytearray(make_header_bytes())
        raw[3] = 0x00 ^ 0xFF
        self.assert_structural(bytes(raw))

    def test_truncated_file(self) -> None:
        self.assert_structural(make_header_bytes()[:48])

    def test_empty_file(self) -> None:
        self.assert_structural(b"")

    def test_bad_version(self) -> None:
        raw = bytearray(make_header_bytes())
        raw[4] = 2
        self.assert_structural(bytes(raw))

    def test_bad_kdf_type(self) -> None:
        raw = bytearray(make_header_bytes())
        raw[5] = 0x02
        self.assert_structural(bytes(raw))

    def test_kdf_out_of_range_memory(self) -> None:
        raw = bytearray(make_header_bytes())
        raw[23:27] = struct.pack(">I", 262145)
        self.assert_structural(bytes(raw))


class TestSidecarRevision:
    def test_missing_sidecar_is_zero(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault.enc"
        assert storage.read_revision(vp) == 0

    def test_valid_sidecar(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault.enc"
        sp = storage.sidecar_path(vp)
        sp.write_bytes(b"17")
        assert storage.read_revision(vp) == 17

    @pytest.mark.parametrize(
        "garbage", [b"", b"abc", b"12x", b"-5", b"2**63", "99999999999999999999999".encode()]
    )
    def test_corrupt_sidecar_zero_with_warning(
        self, tmp_path: Path, garbage: bytes, capsys: pytest.CaptureFixture[str]
    ) -> None:
        vp = tmp_path / "vault.enc"
        storage.sidecar_path(vp).write_bytes(garbage)
        assert storage.read_revision(vp) == 0
        assert "warning" in capsys.readouterr().err


class TestUpdateVaultCycle:
    def test_write_creates_vault_and_sidecar(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault.enc"
        rev = storage.update_vault(vp, lambda ctx: make_payload(ctx.revision_in + 1))
        assert rev == 1
        header, _ = storage.parse_header(storage.read_file_closed(vp) or b"")
        assert header.revision == 1
        assert storage.sidecar_path(vp).read_bytes() == b"1"

    def test_no_tmp_left_behind(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault.enc"
        storage.update_vault(vp, lambda ctx: make_payload(1))
        leftovers = [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
        assert leftovers == []

    def test_corrupt_sidecar_does_not_block_write(
        self, tmp_path: Path
    ) -> None:
        vp = tmp_path / "vault.enc"
        storage.update_vault(vp, lambda ctx: make_payload(5))
        storage.sidecar_path(vp).write_bytes(b"garbage!")
        rev = storage.update_vault(vp, lambda ctx: make_payload(ctx.revision_in + 1))
        # revision_in = max(header=5, sidecar=0) = 5 → новый = 6
        assert rev == 6

    def test_revision_takes_max_of_header_and_sidecar(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault.enc"
        storage.update_vault(vp, lambda ctx: make_payload(10))
        storage.sidecar_path(vp).write_bytes(b"3")
        rev = storage.update_vault(vp, lambda ctx: make_payload(ctx.revision_in + 1))
        assert rev == 11

    def test_rollback_warning_when_header_behind_sidecar(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """§12: header < sidecar → предупреждение о возможном rollback."""
        vp = tmp_path / "vault.enc"
        storage.update_vault(vp, lambda ctx: make_payload(7))
        # Откатываем vault.enc к revision 2, sidecar остаётся на 7.
        vp.write_bytes(make_payload(2))
        capsys.readouterr()
        rev = storage.update_vault(vp, lambda ctx: make_payload(8))
        assert "possible rollback" in capsys.readouterr().err
        assert rev == 8

    def test_no_rollback_warning_in_normal_flow(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        vp = tmp_path / "vault.enc"
        storage.update_vault(vp, lambda ctx: make_payload(3))
        capsys.readouterr()
        storage.update_vault(vp, lambda ctx: make_payload(ctx.revision_in + 1))
        assert "rollback" not in capsys.readouterr().err

    def test_backup_created_on_second_write(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault.enc"
        storage.update_vault(vp, lambda ctx: make_payload(1))
        bak = vp.with_name("vault.enc.bak")
        assert not bak.exists()
        storage.update_vault(vp, lambda ctx: make_payload(ctx.revision_in + 1))
        assert bak.exists()

    def test_lock_released_after_transform_raises(self, tmp_path: Path) -> None:
        """finally-гарантия: исключение в transform не оставляет висящий lock."""
        vp = tmp_path / "vault.enc"

        def boom(ctx: storage.WriteContext) -> bytes:
            raise RuntimeError("injected")

        with pytest.raises(RuntimeError, match="injected"):
            storage.update_vault(vp, boom)

        rev = storage.update_vault(vp, lambda ctx: make_payload(1))
        assert rev == 1

    def test_lock_released_when_vault_absent_and_error_before_write(
        self, tmp_path: Path
    ) -> None:
        vp = tmp_path / "vault.enc"
        with pytest.raises(RuntimeError):
            storage.update_vault(vp, lambda ctx: (_ for _ in ()).throw(RuntimeError()))
        assert not vp.exists()


class TestFsyncOrdering:
    def test_fsync_called_before_replace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []
        real_fsync = os.fsync
        real_replace = os.replace

        def fake_fsync(fd: int) -> None:
            calls.append("fsync")
            real_fsync(fd)

        def fake_replace(src: str, dst: str) -> None:
            calls.append(f"replace:{Path(dst).name}")
            real_replace(src, dst)

        monkeypatch.setattr(os, "fsync", fake_fsync)
        monkeypatch.setattr(os, "replace", fake_replace)

        vp = tmp_path / "vault.enc"
        storage.update_vault(vp, lambda ctx: make_payload(1))
        storage.update_vault(vp, lambda ctx: make_payload(ctx.revision_in + 1))

        # Каждый atomic_write: fsync(tmp) строго перед replace
        # (vault x2 + sidecar x2 = минимум 4 fsync и 4 replace).
        replaces = [i for i, c in enumerate(calls) if c.startswith("replace:")]
        assert len(replaces) >= 4
        for i in replaces:
            assert calls[i - 1] == "fsync"


class TestConcurrency:
    def test_two_parallel_writes_no_lost_update(self, tmp_path: Path) -> None:
        """Тест из §12: два параллельных add → итоговый revision == 2."""
        vp = tmp_path / "vault.enc"
        barrier = threading.Barrier(2)

        def worker(started: list[int]) -> None:
            barrier.wait()
            storage.update_vault(
                vp,
                lambda ctx: make_payload(ctx.revision_in + 1),
                timeout=30.0,
            )
            started.append(1)

        done: list[int] = []
        t1 = threading.Thread(target=worker, args=(done,))
        t2 = threading.Thread(target=worker, args=(done,))
        t1.start()
        t2.start()
        t1.join(timeout=60)
        t2.join(timeout=60)

        assert len(done) == 2
        header, _ = storage.parse_header(storage.read_file_closed(vp) or b"")
        assert header.revision == 2
        assert storage.read_revision(vp) == 2

    def test_busy_lock_times_out_with_structured_error(self, tmp_path: Path) -> None:
        vp = tmp_path / "vault.enc"

        def holder(ctx: storage.WriteContext) -> bytes:
            with pytest.raises(VaultBusyError) as ei:
                storage.update_vault(
                    vp, lambda c: make_payload(1), timeout=0.2
                )
            assert "another operation in progress" in str(ei.value)
            return make_payload(1)

        storage.update_vault(vp, holder)

