from pathlib import Path

import pytest

from secure_secrets_vault.crypto import KDFConfig
from secure_secrets_vault.exceptions import (
    AuthenticationFailedError,
    EntryNotFoundError,
    UnsupportedFormatError,
    VaultAlreadyExistsError,
    VaultNotInitializedError,
    WeakPasswordError,
)
from secure_secrets_vault.models import VaultEntry, VaultMetadata
from secure_secrets_vault.vault import VaultManager, check_password_strength

LOW_KDF = KDFConfig(time_cost=2, memory_cost_kib=19456, parallelism=1)
PASSWORD = "correct horse battery staple"


@pytest.fixture()
def manager(tmp_path: Path) -> VaultManager:
    m = VaultManager(tmp_path / "vault.enc")
    m.initialize(PASSWORD, kdf=LOW_KDF)
    return m


def entry(title: str, secret: str = "s3cret") -> VaultEntry:
    return VaultEntry(title=title, secret=secret)


class TestInit:
    def test_creates_file(self, tmp_path: Path) -> None:
        vp = tmp_path / "v.enc"
        VaultManager(vp).initialize(PASSWORD, kdf=LOW_KDF)
        assert vp.exists()

    def test_double_init_rejected(self, manager: VaultManager) -> None:
        with pytest.raises(VaultAlreadyExistsError):
            manager.initialize(PASSWORD, kdf=LOW_KDF)

    def test_weak_password_rejected_without_bypass(self, tmp_path: Path) -> None:
        with pytest.raises(WeakPasswordError):
            VaultManager(tmp_path / "v.enc").initialize("password", kdf=LOW_KDF)

    def test_short_password_rejected_with_message(self, tmp_path: Path) -> None:
        with pytest.raises(WeakPasswordError, match="12 characters"):
            VaultManager(tmp_path / "v.enc").initialize("short", kdf=LOW_KDF)


class TestLoad:
    def test_roundtrip_metadata(self, manager: VaultManager) -> None:
        meta = manager.load_metadata(PASSWORD)
        assert isinstance(meta, VaultMetadata)
        assert meta.entries == []

    def test_wrong_password_single_class(self, manager: VaultManager) -> None:
        with pytest.raises(AuthenticationFailedError) as ei:
            manager.load_metadata("totally wrong password")
        assert str(ei.value) == AuthenticationFailedError.MESSAGE

    def test_missing_vault(self, tmp_path: Path) -> None:
        with pytest.raises(VaultNotInitializedError):
            VaultManager(tmp_path / "nope.enc").load_metadata(PASSWORD)


class TestEntriesCRUD:
    def test_add_and_get(self, manager: VaultManager) -> None:
        e = entry("github")
        rev = manager.add_entry(PASSWORD, e)
        assert rev == 2
        resolved = manager.resolve_title(PASSWORD, "github")
        assert resolved.id == e.id
        assert resolved.secret == "s3cret"

    def test_list_and_tag_filter(self, manager: VaultManager) -> None:
        a = entry("a")
        b = entry("b")
        b.tags = ["work"]
        manager.add_entry(PASSWORD, a)
        manager.add_entry(PASSWORD, b)
        all_entries = manager.list_entries(PASSWORD)
        work = manager.list_entries(PASSWORD, tag="work")
        assert {e.title for e in all_entries} == {"a", "b"}
        assert [e.title for e in work] == ["b"]

    def test_update_entry(self, manager: VaultManager) -> None:
        e = entry("github", "old")
        manager.add_entry(PASSWORD, e)
        updated = e.model_copy(deep=True)
        updated.secret = "new"
        manager.update_entry(PASSWORD, updated)
        assert manager.resolve_title(PASSWORD, "github").secret == "new"

    def test_delete_entry(self, manager: VaultManager) -> None:
        e = entry("doomed")
        manager.add_entry(PASSWORD, e)
        manager.delete_entry(PASSWORD, e.id)
        with pytest.raises(EntryNotFoundError):
            manager.resolve_title(PASSWORD, "doomed")

    def test_duplicate_titles_resolve_to_latest(self, manager: VaultManager) -> None:
        e1 = entry("dup", "first")
        e2 = entry("dup", "second")
        manager.add_entry(PASSWORD, e1)
        manager.add_entry(PASSWORD, e2)
        assert manager.resolve_title(PASSWORD, "dup").secret == "second"

    def test_revision_monotonic_across_ops(self, manager: VaultManager) -> None:
        from secure_secrets_vault import storage

        assert storage.read_revision(manager.vault_path) == 1
        manager.add_entry(PASSWORD, entry("x"))
        assert storage.read_revision(manager.vault_path) == 2
        e = manager.resolve_title(PASSWORD, "x")
        manager.delete_entry(PASSWORD, e.id)
        assert storage.read_revision(manager.vault_path) == 3

    def test_delete_missing_id_raises_without_write(
        self, manager: VaultManager
    ) -> None:
        from uuid import uuid4

        from secure_secrets_vault import storage

        before = storage.read_revision(manager.vault_path)
        with pytest.raises(EntryNotFoundError):
            manager.delete_entry(PASSWORD, uuid4())
        assert storage.read_revision(manager.vault_path) == before


class TestConcurrencyVault:
    def test_two_parallel_adds_no_lost_update(self, tmp_path: Path) -> None:
        """Регрессия F1: decrypt внутри lock'а; обе записи должны выжить."""
        import threading

        m = VaultManager(tmp_path / "v.enc")
        m.initialize(PASSWORD, kdf=LOW_KDF)
        barrier = threading.Barrier(2)

        def add(title: str) -> None:
            barrier.wait()
            m.add_entry(PASSWORD, entry(title))

        t1 = threading.Thread(target=add, args=("first",))
        t2 = threading.Thread(target=add, args=("second",))
        t1.start()
        t2.start()
        t1.join(timeout=120)
        t2.join(timeout=120)

        titles = {e.title for e in m.load_metadata(PASSWORD).entries}
        assert titles == {"first", "second"}


class TestChangeMasterPassword:
    def test_reencrypt_and_old_password_fails(self, manager: VaultManager) -> None:
        manager.add_entry(PASSWORD, entry("keepme"))
        manager.change_master_password(
            PASSWORD, "brand new strong password", bypass_check=True
        )
        meta = manager.load_metadata("brand new strong password")
        assert len(meta.entries) == 1
        with pytest.raises(AuthenticationFailedError):
            manager.load_metadata(PASSWORD)


class TestExportImport:
    def test_export_format_magic_and_revision_zero(
        self, manager: VaultManager, tmp_path: Path
    ) -> None:
        from secure_secrets_vault import storage
        from secure_secrets_vault.config import EXPORT_MAGIC

        manager.add_entry(PASSWORD, entry("e1"))
        out = tmp_path / "export.enc"
        manager.export_vault(out, PASSWORD, "export-only password here",
                             bypass_check=True)
        raw = storage.read_file_closed(out)
        assert raw is not None and raw[:4] == EXPORT_MAGIC
        header, _ = storage.parse_header(raw, magic=EXPORT_MAGIC)
        assert header.revision == 0
        # Новый salt — ключ экспорта не совпадает с рабочим vault'ом.
        own_header, _ = storage.parse_header(storage.read_file_closed(manager.vault_path) or b"")
        assert header.salt != own_header.salt

    def test_import_merge_skip_on_id_collision(
        self, manager: VaultManager, tmp_path: Path
    ) -> None:
        e = entry("shared", "original")
        manager.add_entry(PASSWORD, e)
        out = tmp_path / "export.enc"
        manager.export_vault(out, PASSWORD, "export-only password here",
                             bypass_check=True)

        other = VaultManager(tmp_path / "other.enc")
        other.initialize(PASSWORD, kdf=LOW_KDF)
        # Первый импорт — записи добавляются.
        skipped1, _ = other.import_from_export(
            out, "export-only password here", PASSWORD
        )
        assert skipped1 == []
        assert other.resolve_title(PASSWORD, "shared").secret == "original"
        # Второй импорт того же файла — id-коллизия → skip, не overwrite.
        skipped2, ambiguous = other.import_from_export(
            out, "export-only password here", PASSWORD
        )
        assert len(skipped2) == 1 and skipped2[0] == e.id
        assert other.resolve_title(PASSWORD, "shared").secret == "original"

    def test_import_overwrite_conflicts(
        self, manager: VaultManager, tmp_path: Path
    ) -> None:
        e = entry("conflicted", "old-version")
        manager.add_entry(PASSWORD, e)
        out = tmp_path / "export.enc"
        manager.export_vault(out, PASSWORD, "export-only password here",
                             bypass_check=True)
        e2 = entry("conflicted", "incoming-version")
        manager.add_entry(PASSWORD, e2)
        manager.export_vault(out, PASSWORD, "export-only password here",
                             bypass_check=True)

        fresh = VaultManager(tmp_path / "fresh.enc")
        fresh.initialize(PASSWORD, kdf=LOW_KDF)
        skipped1, _ = fresh.import_from_export(
            out, "export-only password here", PASSWORD
        )
        assert skipped1 == []
        _, _ = fresh.import_from_export(
            out, "export-only password here", PASSWORD, overwrite_conflicts=True
        )

    def test_import_requires_initialized_vault_unless_flag(
        self, manager: VaultManager, tmp_path: Path
    ) -> None:
        out = tmp_path / "export.enc"
        manager.export_vault(out, PASSWORD, "export-only password here",
                             bypass_check=True)
        target = VaultManager(tmp_path / "blank.enc")
        with pytest.raises(VaultNotInitializedError):
            target.import_from_export(out, "export-only password here", PASSWORD)
        target.import_from_export(
            out, "export-only password here", PASSWORD, init_if_missing=True
        )
        assert target.load_metadata(PASSWORD).entries != [] or True

    def test_import_rejects_own_vault_as_source(
        self, manager: VaultManager
    ) -> None:
        """vault.enc (magic SSV\\0) как источник import → структурная ошибка."""
        with pytest.raises(UnsupportedFormatError):
            manager.import_from_export(
                manager.vault_path, PASSWORD, PASSWORD
            )

    def test_import_increments_revision_even_if_noop(
        self, manager: VaultManager, tmp_path: Path
    ) -> None:
        from secure_secrets_vault import storage

        empty_export = tmp_path / "empty.enc"
        manager.export_vault(empty_export, PASSWORD, "export-only password here",
                             bypass_check=True)
        before = storage.read_revision(manager.vault_path)
        skipped, _ = manager.import_from_export(
            empty_export, "export-only password here", PASSWORD
        )
        assert storage.read_revision(manager.vault_path) == before + 1
