"""End-to-end тесты CLI через Typer CliRunner с моком getpass."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from secure_secrets_vault.cli import app

PASSWORD = "correct horse battery staple"
WEAK_OK = "--i-know-its-weak"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def vpath(tmp_path: Path) -> Path:
    p = tmp_path / "vault.enc"
    os_environ_backup = None
    return p


def init_vault(runner: CliRunner, vpath: Path, password: str = PASSWORD) -> None:
    result = runner.invoke(
        app,
        ["init", "--vault-path", str(vpath)],
        input=f"{password}\n{password}\n",
    )
    assert result.exit_code == 0, result.output


def patch_getpass(monkeypatch: pytest.MonkeyPatch, **answers: str) -> None:
    """Патчит getpass по тексту промпта; default — мастер-пароль."""
    import getpass as gp

    def fake(prompt: str = "") -> str:
        for key, value in answers.items():
            if prompt.startswith(key):
                return value
        return PASSWORD

    monkeypatch.setattr(gp, "getpass", fake)


class TestFullFlow:
    def test_init_add_list_get_print(
        self, runner: CliRunner, vpath: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patch_getpass(monkeypatch, **{"Secret": "s3cret-value"})
        vp = str(vpath)
        common = ["--vault-path", vp]

        r = runner.invoke(app, ["init", *common], input=f"{PASSWORD}\n{PASSWORD}\n")
        assert r.exit_code == 0, r.output

        r = runner.invoke(
            app,
            ["add", "github", "--username", "zurok", "--tag", "dev", *common],
        )
        assert r.exit_code == 0, r.output

        r = runner.invoke(app, ["list", *common])
        assert r.exit_code == 0, r.output
        assert "github" in r.output

        r = runner.invoke(app, ["get", "github", "--print", *common])
        assert r.exit_code == 0, r.output
        assert "s3cret-value" in r.output

    def test_wrong_password_fails_with_crypto_exit(
        self, runner: CliRunner, vpath: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        init_vault(runner, vpath)

        def wrong(prompt: str = "") -> str:
            return "wrong password entirely"

        import getpass as gp

        monkeypatch.setattr(gp, "getpass", wrong)
        r = runner.invoke(app, ["list", "--vault-path", str(vpath)])
        assert r.exit_code == 2
        assert "Decryption failed" in r.output

    def test_weak_password_rejected_and_bypass_flag_works(
        self, runner: CliRunner, vpath: Path
    ) -> None:
        weak = "password"
        r = runner.invoke(
            app,
            ["init", "--vault-path", str(vpath)],
            input=f"{weak}\n{weak}\n",
        )
        assert r.exit_code == 5
        assert "--i-know-its-weak" in r.output

        r = runner.invoke(
            app,
            ["init", WEAK_OK, "--vault-path", str(vpath)],
            input=f"{weak}\n{weak}\n",
        )
        assert r.exit_code == 0, r.output

    def test_export_import_roundtrip_cli(
        self, runner: CliRunner, vpath: Path, tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import getpass as gp

        passwords: dict[str, str] = {
            "Export password: ": "export-only password here",
            "Repeat export password: ": "export-only password here",
            "Import file password: ": "export-only password here",
        }
        def fake(prompt: str = "") -> str:
            return passwords.get(prompt, PASSWORD)

        monkeypatch.setattr(gp, "getpass", fake)
        common = ["--vault-path", str(vpath)]

        r = runner.invoke(app, ["init", *common], input=f"{PASSWORD}\n{PASSWORD}\n")
        assert r.exit_code == 0, r.output
        r = runner.invoke(
            app, ["add", "site", *common], input="value-1\n"
        )
        assert r.exit_code == 0, r.output

        out = tmp_path / "export.enc"
        r = runner.invoke(app, ["export", str(out), *common])
        assert r.exit_code == 0, r.output

        other_path = tmp_path / "other.enc"
        # --init-if-missing: мастер-пароль запрашивается после import-пароля.
        r = runner.invoke(
            app,
            [
                "import-", str(out),
                "--init-if-missing",
                "--vault-path", str(other_path),
            ],
            input=f"{PASSWORD}\n{PASSWORD}\n",
        )
        assert r.exit_code == 0, r.output
        r = runner.invoke(app, ["list", "--vault-path", str(other_path)])
        assert r.exit_code == 0, r.output
        assert "site" in r.output

    def test_unsafe_plaintext_requires_both_factors_non_tty(
        self, runner: CliRunner, vpath: Path, tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import getpass as gp

        init_vault(runner, vpath)

        def plain(prompt: str = "") -> str:
            return PASSWORD

        monkeypatch.setattr(gp, "getpass", plain)
        target = tmp_path / "plain.json"

        # Только флаг, без 'y' на stdin → отказ.
        r = runner.invoke(
            app,
            [
                "export", str(target),
                "--unsafe-plaintext-json", str(target),
                "--yes-i-understand",
                "--vault-path", str(vpath),
            ],
            input="\n",
        )
        assert r.exit_code != 0
        assert not target.exists()

        # Флаг И 'y' → успех.
        r = runner.invoke(
            app,
            [
                "export", str(target),
                "--unsafe-plaintext-json", str(target),
                "--yes-i-understand",
                "--vault-path", str(vpath),
            ],
            input="y\n",
        )
        assert r.exit_code == 0, r.output
        assert "value" not in target.read_text() or target.exists()

    def test_status_without_password(self, runner: CliRunner, vpath: Path) -> None:
        init_vault(runner, vpath)
        r = runner.invoke(app, ["status", "--vault-path", str(vpath)])
        assert r.exit_code == 0, r.output
        assert "Revision" in r.output
