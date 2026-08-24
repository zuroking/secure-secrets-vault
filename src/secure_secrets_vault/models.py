"""Pydantic v2-схемы: без крипто, без I/O."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class VaultEntry(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    username: str | None = None
    secret: str
    notes: str | None = None
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class VaultMetadata(BaseModel):
    schema_version: int = 1
    entries: list[VaultEntry] = Field(default_factory=list)


class KDFConfig(BaseModel):
    time_cost: int = 3
    memory_cost_kib: int = 65536
    parallelism: int = 4
    hash_len: int = 32
    salt_len: int = 16
