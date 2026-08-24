"""Typer CLI поверх VaultManager. Rich-вывод, getpass для паролей."""

import os
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import config, generator
from .clipboard import copy_with_autoclear
from .exceptions import (
    AuthenticationFailedError,
    ClipboardError,
    EntryNotFoundError,
    UnsupportedFormatError,
    VaultBusyError,
    VaultError,
    VaultNotInitializedError,
)
from .models import KDFConfig, VaultEntry
from .vault import VaultManager

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()
err_console = Console(stderr=True)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CRYPTO = 2
EXIT_STRUCTURAL = 3
EXIT_BUSY = 4
EXIT_WEAK = 5
EXIT_NOT_FOUND = 6


def _manager(vault_path: Path) -> VaultManager:
    return VaultManager(vault_path)


def _prompt_password(confirm: bool = False) -> str:
    import getpass

    pw = getpass.getpass("Master password: ")
    if confirm:
        again = getpass.getpass("Repeat master password: ")
        if pw != again:
            err_console.print("[red]Passwords do not match.[/red]")
            raise typer.Exit(EXIT_ERROR)
    return pw


def _fail(exc: Exception) -> None:
    err_console.print(f"[red]{exc}[/red]")
    if isinstance(exc, AuthenticationFailedError):
        raise typer.Exit(EXIT_CRYPTO) from exc
    if isinstance(exc, UnsupportedFormatError):
        raise typer.Exit(EXIT_STRUCTURAL) from exc
    if isinstance(exc, VaultBusyError):
        raise typer.Exit(EXIT_BUSY) from exc
    if isinstance(exc, EntryNotFoundError):
        raise typer.Exit(EXIT_NOT_FOUND) from exc
    from .exceptions import WeakPasswordError

    if isinstance(exc, WeakPasswordError):
        raise typer.Exit(EXIT_WEAK) from exc
    raise typer.Exit(EXIT_ERROR) from exc


@app.command()
def init(
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
    time_cost: Annotated[int, typer.Option(min=2, max=10)] = 3,
    memory_cost: Annotated[int, typer.Option(min=19456, max=262144)] = 65536,
    parallelism: Annotated[int, typer.Option(min=1, max=8)] = 4,
    i_know_its_weak: Annotated[bool, typer.Option("--i-know-its-weak")] = False,
) -> None:
    """Создать новый vault и задать мастер-пароль."""
    path = vault_path or config.default_vault_path()
    kdf = KDFConfig(time_cost=time_cost, memory_cost_kib=memory_cost, parallelism=parallelism)
    try:
        _manager(path).initialize(
            _prompt_password(confirm=True), kdf=kdf, bypass_check=i_know_its_weak
        )
    except VaultError as exc:
        _fail(exc)
    console.print(f"[green]Vault initialized:[/green] {path}")


@app.command()
def add(
    title: str,
    username: Annotated[Optional[str], typer.Option()] = None,
    notes: Annotated[Optional[str], typer.Option()] = None,
    tag: Annotated[list[str], typer.Option()] = [],
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
) -> None:
    """Добавить запись (секрет вводится скрыто)."""
    import getpass

    secret = getpass.getpass("Secret: ")
    entry = VaultEntry(title=title, username=username, secret=secret, notes=notes, tags=list(tag))
    try:
        _manager(vault_path or config.default_vault_path()).add_entry(
            _prompt_password(), entry
        )
    except VaultError as exc:
        _fail(exc)
    console.print(f"[green]Entry added:[/green] {title}")


@app.command()
def get(
    title: str,
    print_secret: Annotated[
        bool,
        typer.Option("--print", help="Вывести в stdout вместо буфера (без autoclear)."),
    ] = False,
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
) -> None:
    """Показать / скопировать запись."""
    try:
        manager = _manager(vault_path or config.default_vault_path())
        password = _prompt_password()
        entry = manager.resolve_title(password, title)
        dupes = [e for e in manager.list_entries(password) if e.title == title]
    except VaultError as exc:
        _fail(exc)

    if len(dupes) > 1:
        err_console.print(
            f"[yellow]warning: multiple entries titled {title!r}; "
            "showing the latest added[/yellow]"
        )

    if print_secret:
        console.print(entry.secret)
        return

    try:
        copy_with_autoclear(entry.secret)
        console.print(
            f"[green]Copied to clipboard.[/green] Auto-clear in "
            f"{config.CLIPBOARD_CLEAR_DELAY_SECONDS}s."
        )
    except ClipboardError as exc:
        _fail(exc)


@app.command("list")
def list_entries(
    tag: Annotated[Optional[str], typer.Option()] = None,
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
) -> None:
    """Список записей без секретов."""
    try:
        entries = _manager(vault_path or config.default_vault_path()).list_entries(
            _prompt_password(), tag=tag
        )
    except VaultError as exc:
        _fail(exc)

    table = Table(show_header=True)
    table.add_column("Title")
    table.add_column("Username")
    table.add_column("Tags")
    for e in entries:
        table.add_row(e.title, e.username or "", ", ".join(e.tags))
    console.print(table)


@app.command()
def update(
    title: str,
    username: Annotated[Optional[str], typer.Option()] = None,
    notes: Annotated[Optional[str], typer.Option()] = None,
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
) -> None:
    """Изменить запись (секрет вводится скрыто заново)."""
    import getpass

    try:
        manager = _manager(vault_path or config.default_vault_path())
        password = _prompt_password()
        entry = manager.resolve_title(password, title)
        secret = getpass.getpass("New secret (empty = keep): ") or entry.secret
        updated = entry.model_copy(deep=True)
        updated.secret = secret
        if username is not None:
            updated.username = username
        if notes is not None:
            updated.notes = notes
        manager.update_entry(password, updated)
    except VaultError as exc:
        _fail(exc)
    console.print(f"[green]Entry updated:[/green] {title}")


@app.command()
def delete(
    title: str,
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
) -> None:
    """Удалить запись."""
    try:
        manager = _manager(vault_path or config.default_vault_path())
        password = _prompt_password()
        entry = manager.resolve_title(password, title)
        if not typer.confirm(f"Delete {title!r}?"):
            raise typer.Exit(EXIT_OK)
        manager.delete_entry(password, entry.id)
    except VaultError as exc:
        _fail(exc)
    console.print(f"[green]Deleted:[/green] {title}")


@app.command()
def generate(
    length: Annotated[int, typer.Option(min=8)] = 20,
    no_symbols: Annotated[bool, typer.Option()] = False,
    passphrase: Annotated[bool, typer.Option()] = False,
) -> None:
    """Сгенерировать пароль (не требует unlock)."""
    if passphrase:
        console.print(generator.generate_passphrase())
    else:
        console.print(generator.generate_password(length, use_specials=not no_symbols))


@app.command("change-master-password")
def change_master_password(
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
    i_know_its_weak: Annotated[bool, typer.Option("--i-know-its-weak")] = False,
) -> None:
    """Re-encrypt с новым паролем и новым salt."""
    try:
        _manager(vault_path or config.default_vault_path()).change_master_password(
            _prompt_password(),
            _prompt_password(confirm=True),
            bypass_check=i_know_its_weak,
        )
    except VaultError as exc:
        _fail(exc)
    console.print("[green]Master password changed (new salt generated).[/green]")


@app.command()
def export(
    out: Path,
    unsafe_plaintext_json: Annotated[
        Optional[Path],
        typer.Option(
            "--unsafe-plaintext-json",
            help="Опасно: экспорт в plaintext JSON вместо зашифрованного формата.",
        ),
    ] = None,
    yes_i_understand: Annotated[bool, typer.Option("--yes-i-understand")] = False,
    i_know_its_weak: Annotated[bool, typer.Option("--i-know-its-weak")] = False,
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
) -> None:
    """Зашифрованный экспорт (новый пароль обязателен)."""
    if unsafe_plaintext_json is not None:
        _export_unsafe(unsafe_plaintext_json, yes_i_understand, vault_path)
        return
    try:
        _manager(vault_path or config.default_vault_path()).export_vault(
            out,
            _prompt_password(),
            _prompt_export_password(confirm=True),
            bypass_check=i_know_its_weak,
        )
    except VaultError as exc:
        _fail(exc)
    console.print(f"[green]Exported:[/green] {out}")


def _prompt_export_password(confirm: bool = False) -> str:
    import getpass

    pw = getpass.getpass("Export password: ")
    if confirm:
        again = getpass.getpass("Repeat export password: ")
        if pw != again:
            err_console.print("[red]Passwords do not match.[/red]")
            raise typer.Exit(EXIT_ERROR)
    return pw


def _confirm_unsafe(yes_i_understand: bool) -> None:
    """Оба фактора на неинтерактивном пути: --yes-i-understand И 'y' из stdin."""
    if sys.stdin.isatty():
        if not typer.confirm(
            "Write SECRETS IN PLAINTEXT to a file? This is dangerous."
        ):
            raise typer.Exit(EXIT_OK)
        return
    if not yes_i_understand:
        err_console.print(
            "[red]Non-interactive plaintext export requires both "
            "--yes-i-understand AND literal 'y' on stdin.[/red]"
        )
        raise typer.Exit(EXIT_ERROR)
    answer = sys.stdin.readline().strip().lower()
    if answer != "y":
        err_console.print("[red]stdin confirmation missing ('y' expected).[/red]")
        raise typer.Exit(EXIT_ERROR)


def _export_unsafe(out: Path, yes_i_understand: bool, vault_path: Optional[Path]) -> None:
    _confirm_unsafe(yes_i_understand)
    try:
        meta = _manager(vault_path or config.default_vault_path()).load_metadata(
            _prompt_password()
        )
    except VaultError as exc:
        _fail(exc)
    out.write_text(meta.model_dump_json(indent=2), encoding="utf-8")
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    err_console.print(
        f"[red]WARNING: plaintext secrets written to {out}. Delete it after use.[/red]"
    )


@app.command()
def import_(
    file: Annotated[Path, typer.Argument()],
    init_if_missing: Annotated[bool, typer.Option("--init-if-missing")] = False,
    overwrite_conflicts: Annotated[bool, typer.Option("--overwrite-conflicts")] = False,
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
) -> None:
    """Импорт из зашифрованного экспорта (merge-семантика)."""
    try:
        skipped, ambiguous = _manager(vault_path or config.default_vault_path()).import_from_export(
            file,
            _prompt_import_password(),
            _prompt_password(),
            overwrite_conflicts=overwrite_conflicts,
            init_if_missing=init_if_missing,
        )
    except VaultError as exc:
        _fail(exc)
    if skipped:
        err_console.print(
            f"[yellow]Skipped (id collision): {len(skipped)} entry(ies)[/yellow]"
        )
    if ambiguous:
        err_console.print(
            f"[yellow]Ambiguous duplicate titles: {', '.join(ambiguous)}[/yellow]"
        )
    console.print("[green]Import complete.[/green]")


def _prompt_import_password() -> str:
    import getpass

    return getpass.getpass("Import file password: ")


@app.command()
def status(
    vault_path: Annotated[Optional[Path], typer.Option(help="Путь к vault-файлу.")] = None,
) -> None:
    """Revision, кол-во записей, путь к .bak (не требует пароля)."""
    from . import storage

    path = vault_path or config.default_vault_path()
    raw = storage.read_file_closed(path)
    revision = storage.read_revision(path)
    exists = raw is not None
    entries = "?"
    if exists:
        try:
            header, _ = storage.parse_header(raw)  # type: ignore[arg-type]
            revision = max(revision, header.revision)
        except UnsupportedFormatError:
            pass
    bak = path.with_name(path.name + ".bak")
    console.print(f"Vault:      {path}")
    console.print(f"Exists:     {'yes' if exists else 'no'}")
    console.print(f"Revision:   {revision}")
    console.print(f"Entries:    {entries}")
    console.print(f"Backup:     {bak} ({'present' if bak.exists() else 'absent'})")


if __name__ == "__main__":
    app()
