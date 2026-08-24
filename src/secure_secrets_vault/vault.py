"""VaultManager — оркестрация crypto + storage. Бизнес-логика vault'а."""

import datetime as dt
import os
from collections.abc import Callable
from pathlib import Path
from typing import TypeAlias
from uuid import UUID

from pydantic import ValidationError

from . import config, crypto, storage
from .config import (
    EXPORT_MAGIC,
    FORMAT_VERSION,
    HEADER_MAGIC,
    KDF_TYPE_ARGON2ID,
    MIN_PASSWORD_LENGTH,
)
from .exceptions import (
    EntryNotFoundError,
    UnsupportedFormatError,
    VaultAlreadyExistsError,
    VaultError,
    VaultNotInitializedError,
    WeakPasswordError,
)
from .models import KDFConfig, VaultEntry, VaultMetadata
from .password_policy import COMMON_PASSWORDS

MetadataTransform: TypeAlias = Callable[[VaultMetadata], VaultMetadata]


def check_password_strength(password: str, *, bypass: bool = False) -> None:
    """Минимальная проверка: длина >= 12 и не во встроенном списке утёкших.

    Не блокирует жёстко при bypass=True (--i-know-its-weak). Без сети.
    """
    if bypass:
        return
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"at least {MIN_PASSWORD_LENGTH} characters")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("not present in the common leaked passwords list")
    if problems:
        raise WeakPasswordError(
            "weak master password: " + " and ".join(problems)
            + " (use --i-know-its-weak to override)"
        )


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class VaultManager:
    """Один вызов CLI == один экземпляр; ключ живёт ровно на операцию."""

    def __init__(self, vault_path: Path) -> None:
        self.vault_path = vault_path

    # ---------- сериализация / шифрование ----------

    @staticmethod
    def _build_payload(
        key: bytes,
        salt: bytes,
        kdf: KDFConfig,
        revision: int,
        metadata: VaultMetadata,
        magic: bytes = HEADER_MAGIC,
    ) -> bytes:
        """Заголовок сериализуется один раз; AAD = тот же буфер [0:AAD_LEN)."""
        crypto.validate_kdf_params(kdf)
        nonce = crypto.new_nonce()
        header = storage.VaultHeader(
            magic=magic,
            version=FORMAT_VERSION,
            kdf_type=KDF_TYPE_ARGON2ID,
            salt=salt,
            time_cost=kdf.time_cost,
            memory_cost_kib=kdf.memory_cost_kib,
            parallelism=kdf.parallelism,
            hash_len=kdf.hash_len,
            revision=revision,
            nonce=nonce,
        )
        header_bytes = storage.serialize_header(header)
        aad = header_bytes[: config.AAD_LEN]
        plaintext = metadata.model_dump_json().encode("utf-8")
        return header_bytes + crypto.encrypt(key, plaintext, nonce, aad)

    def _decrypt_raw(
        self, raw: bytes, password: str, magic: bytes = HEADER_MAGIC
    ) -> tuple[bytes, VaultMetadata]:
        header, ciphertext = storage.parse_header(raw, magic=magic)
        kdf = storage.header_to_kdf_config(header)
        key = crypto.derive_key(password, header.salt, kdf)
        aad = raw[: config.AAD_LEN]  # slice прочитанных с диска байтов
        plaintext = crypto.decrypt(key, ciphertext, header.nonce, aad)
        try:
            metadata = VaultMetadata.model_validate_json(plaintext.decode("utf-8"))
        except ValidationError:
            # Без `from exc`: текст ValidationError включает input_value,
            # т.е. значения полей из расшифрованного JSON (§11).
            raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE) from None
        return key, metadata

    # ---------- чтение ----------

    def load_metadata(self, password: str) -> VaultMetadata:
        raw = storage.read_file_closed(self.vault_path)
        if raw is None:
            raise VaultNotInitializedError("vault is not initialized")
        _, metadata = self._decrypt_raw(raw, password)
        return metadata

    def list_entries(self, password: str, tag: str | None = None) -> list[VaultEntry]:
        entries = self.load_metadata(password).entries
        if tag is not None:
            entries = [e for e in entries if tag in e.tags]
        return sorted(entries, key=lambda e: e.created_at)

    def resolve_title(self, password: str, title: str) -> VaultEntry:
        """Дубли title резолвятся по последней добавленной с warning'ом CLI."""
        matches = [
            e for e in self.load_metadata(password).entries if e.title == title
        ]
        if not matches:
            raise EntryNotFoundError(f"no entry titled {title!r}")
        return max(matches, key=lambda e: e.created_at)

    # ---------- запись ----------

    def initialize(
        self, password: str, kdf: KDFConfig | None = None,
        *, bypass_check: bool = False,
    ) -> None:
        check_password_strength(password, bypass=bypass_check)
        cfg = kdf or KDFConfig()
        salt = os.urandom(16)
        key = crypto.derive_key(password, salt, cfg)

        def build(ctx: storage.WriteContext) -> bytes:
            # Проверка существования внутри критической секции — иначе
            # два конкурентных init оба проходят exists() и второй тихо
            # перезаписывает первый (race check-then-act).
            if ctx.current_raw is not None:
                raise VaultAlreadyExistsError("vault already exists at this path")
            return self._build_payload(key, salt, cfg, 1, VaultMetadata())

        if self.vault_path.exists():
            raise VaultAlreadyExistsError("vault already exists at this path")
        storage.update_vault(self.vault_path, build)

    def add_entry(self, password: str, entry: VaultEntry) -> int:
        def transform(meta: VaultMetadata) -> VaultMetadata:
            meta.entries.append(entry)
            return meta

        return self._transform(password, transform)

    def update_entry(self, password: str, updated: VaultEntry) -> int:
        updated.updated_at = _utcnow()

        def transform(meta: VaultMetadata) -> VaultMetadata:
            if not any(e.id == updated.id for e in meta.entries):
                raise EntryNotFoundError(f"no entry with id {updated.id}")
            meta.entries = [updated if e.id == updated.id else e for e in meta.entries]
            return meta

        return self._transform(password, transform)

    def delete_entry(self, password: str, entry_id: UUID) -> int:
        def transform(meta: VaultMetadata) -> VaultMetadata:
            if not any(e.id == entry_id for e in meta.entries):
                raise EntryNotFoundError(f"no entry with id {entry_id}")
            meta.entries = [e for e in meta.entries if e.id != entry_id]
            return meta

        return self._transform(password, transform)

    def change_master_password(
        self, old_password: str, new_password: str, *, bypass_check: bool = False
    ) -> int:
        check_password_strength(new_password, bypass=bypass_check)
        raw = storage.read_file_closed(self.vault_path)
        if raw is None:
            raise VaultNotInitializedError("vault is not initialized")
        header, _ = storage.parse_header(raw)
        _, metadata = self._decrypt_raw(raw, old_password)
        # Наследуем KDF-параметры из старого заголовка, а не дефолты —
        # иначе change-master-password тихо откатывает пользовательские
        # --time-cost/--memory-cost/--parallelism.
        new_kdf = storage.header_to_kdf_config(header)
        new_salt = os.urandom(16)
        new_key = crypto.derive_key(new_password, new_salt, new_kdf)

        def build(ctx: storage.WriteContext) -> bytes:
            return self._build_payload(
                new_key, new_salt, new_kdf, ctx.revision_in + 1, metadata
            )

        return storage.update_vault(self.vault_path, build)

    def export_vault(
        self,
        out_path: Path,
        password: str,
        export_password: str,
        *,
        bypass_check: bool = False,
    ) -> None:
        """Всегда новый salt/nonce/пароль; magic b"SSVE"; revision = 0."""
        if out_path.resolve() == self.vault_path.resolve():
            raise VaultError("export path must differ from the vault path")
        check_password_strength(export_password, bypass=bypass_check)
        metadata = self.load_metadata(password)
        salt = os.urandom(16)
        kdf = KDFConfig()
        key = crypto.derive_key(export_password, salt, kdf)
        payload = self._build_payload(
            key, salt, kdf, 0, metadata, magic=EXPORT_MAGIC
        )
        # Прямой atomic-write без sidecar/.bak/.lock — экспорт не является
        # продолжением истории vault'а и не должен плодить служебные файлы.
        storage.atomic_write_file(out_path, payload)

    def import_from_export(
        self,
        import_file: Path,
        import_password: str,
        own_password: str,
        *,
        overwrite_conflicts: bool = False,
        init_if_missing: bool = False,
    ) -> tuple[list[UUID], list[str]]:
        """Merge-семантика §10. Возвращает (skipped_ids, ambiguous_titles).

        Решение о коллизии принимается ВНУТРИ критической секции (иначе
        параллельный писатель меняет id-набор между снимком и записью).
        revision инкрементируется даже при no-op import — инвариант
        "revision == число записей файла" (§10).
        """
        raw = storage.read_file_closed(import_file)
        if raw is None or raw[:4] != EXPORT_MAGIC:
            raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE)
        incoming = self._decrypt_raw(raw, import_password, magic=EXPORT_MAGIC)[1]

        if not self.vault_path.exists():
            if not init_if_missing:
                raise VaultNotInitializedError(
                    "vault is not initialized (use --init-if-missing)"
                )
            self.initialize(own_password)

        skipped: list[UUID] = []
        ambiguous: list[str] = []

        def transform(meta: VaultMetadata) -> VaultMetadata:
            by_id: dict[UUID, VaultEntry] = {}
            for entry in meta.entries:
                by_id[entry.id] = entry
            for entry in incoming.entries:
                if entry.id in by_id and not overwrite_conflicts:
                    skipped.append(entry.id)
                    continue
                by_id[entry.id] = entry

            titles: set[str] = set()
            seen_dup: set[str] = set()
            merged = list(by_id.values())
            for entry in merged:
                if entry.title in titles and entry.title not in seen_dup:
                    seen_dup.add(entry.title)
                    ambiguous.append(entry.title)
                titles.add(entry.title)
            meta.entries = merged
            return meta

        self._transform(own_password, transform)
        return skipped, ambiguous

    # ---------- внутренний конвейер записи ----------

    def _transform(self, password: str, transform: MetadataTransform) -> int:
        """Мутация под lock'ом: чтение+decrypt выполняются ВНУТРИ
        критической секции update_vault (иначе два параллельных add дают
        lost update — оба расшифровывают устаревший снимок вне lock'а).
        """
        def build(ctx: storage.WriteContext) -> bytes:
            if ctx.current_raw is None:
                raise VaultNotInitializedError("vault is not initialized")
            raw = ctx.current_raw
            header, ciphertext = storage.parse_header(raw)
            kdf = storage.header_to_kdf_config(header)
            key = crypto.derive_key(password, header.salt, kdf)
            plaintext = crypto.decrypt(
                key, ciphertext, header.nonce, raw[: config.AAD_LEN]
            )
            try:
                metadata = VaultMetadata.model_validate_json(
                    plaintext.decode("utf-8")
                )
            except ValidationError:
                raise UnsupportedFormatError(UnsupportedFormatError.MESSAGE) from None

            mutated = transform(metadata)

            return self._build_payload(
                key, header.salt, kdf, ctx.revision_in + 1, mutated
            )

        # Быстрый fail-fast без lock'а; финальная проверка — внутри build.
        if storage.read_file_closed(self.vault_path) is None:
            raise VaultNotInitializedError("vault is not initialized")
        return storage.update_vault(self.vault_path, build)
