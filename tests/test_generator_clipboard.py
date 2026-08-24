import re
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from secure_secrets_vault import clipboard, generator


class TestGenerator:
    def test_length_and_charset(self) -> None:
        pw = generator.generate_password(24)
        assert len(pw) == 24

    def test_min_digits_and_specials(self) -> None:
        for _ in range(20):
            pw = generator.generate_password(16, min_digits=3, min_specials=2)
            assert len(re.findall(r"[0-9]", pw)) >= 3
            assert len(re.findall(r"[!@#$%^&*()\-_=+\[\]{};:,.<>?]", pw)) >= 2

    def test_no_random_module_usage(self) -> None:
        src = Path(generator.__file__).read_text(encoding="utf-8")
        assert "import random" not in src

    def test_too_short_rejected(self) -> None:
        with pytest.raises(ValueError):
            generator.generate_password(4)

    def test_minimums_exceeding_length_rejected(self) -> None:
        with pytest.raises(ValueError):
            generator.generate_password(8, min_digits=50)

    def test_passphrase_format(self) -> None:
        phrase = generator.generate_passphrase(5)
        assert len(phrase.split("-")) == 5

    def test_distribution_not_constant(self) -> None:
        assert len({generator.generate_password(12) for _ in range(10)}) > 1


class TestSecretHash:
    def test_sha256_hex(self) -> None:
        import hashlib

        assert clipboard.secret_hash("abc") == hashlib.sha256(b"abc").hexdigest()

    def test_differs_per_secret(self) -> None:
        assert clipboard.secret_hash("a") != clipboard.secret_hash("b")


class TestHashFileNotInArgv:
    """§12: secret hash не встречается в списке аргументов Popen."""

    def test_argv_contains_path_not_hash(self, tmp_path: Path) -> None:
        captured: dict[str, object] = {}

        def fake_popen(args: list[str], **kwargs: object) -> mock.Mock:
            captured["args"] = list(args)
            return mock.Mock()

        import pyperclip

        with (
            mock.patch.object(pyperclip, "copy"),
            mock.patch.object(subprocess, "Popen", side_effect=fake_popen),
        ):
            secret = "my-secret-value-123"
            clipboard.copy_with_autoclear(secret, delay=1)

        argv = [str(a) for a in captured["args"]]
        assert clipboard.secret_hash(secret) not in " ".join(argv)
        assert "--hash-file" in argv

    def test_popen_fail_cleans_tempfile(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import pyperclip

        created: list[Path] = []
        real_mkstemp = __import__("tempfile").mkstemp

        def tracking_mkstemp(*a: object, **kw: object) -> tuple[int, str]:
            fd, name = real_mkstemp(*a, **kw)  # type: ignore[arg-type]
            created.append(Path(name))
            return fd, name

        with (
            mock.patch.object(pyperclip, "copy"),
            mock.patch.object(
                subprocess, "Popen", side_effect=OSError("no spawn on CI")
            ),
            mock.patch("secure_secrets_vault.clipboard.tempfile.mkstemp", side_effect=tracking_mkstemp),
        ):
            result = clipboard.copy_with_autoclear("secret", delay=1)

        assert result is False
        assert all(not p.exists() for p in created), "tempfile must be cleaned up"
        assert "warning" in capsys.readouterr().err

    def test_successful_spawn_leaves_unlink_to_helper(self) -> None:
        import pyperclip

        with (
            mock.patch.object(pyperclip, "copy"),
            mock.patch.object(subprocess, "Popen") as mp,
            mock.patch.object(Path, "unlink") as munlink,
        ):
            assert clipboard.copy_with_autoclear("s", delay=1) is True
            mp.assert_called_once()
            # Родитель не unlink'ает при успешном spawn — это делает helper.
            munlink.assert_not_called()
