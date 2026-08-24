class VaultError(Exception):
    """Базовый класс всех ошибок vault'а.

    Секрет/пароль никогда не попадает в сообщения исключений.
    """


class VaultBusyError(VaultError):
    """Lock занят другим процессом дольше таймаута."""


class UnsupportedFormatError(VaultError):
    """Структурная ошибка заголовка: bad magic / version / kdf_type / KDF-диапазоны.

    Единое сообщение на весь структурный класс (см. ARCHITECTURE.md §6) —
    без детализации до конкретного нарушенного поля.
    """

    MESSAGE = "vault file is invalid or unsupported"


class CorruptedVaultError(UnsupportedFormatError):
    """Псевдоним структурного класса для обратной совместимости импортов."""


class AuthenticationFailedError(VaultError):
    """Крипто-ошибка: неверный GCM-тег.

    Единое сообщение и единый exit code для wrong password и corrupted
    ciphertext — разный код сам стал бы oracle.
    """

    MESSAGE = "Decryption failed: wrong password or corrupted vault"


class WrongPasswordError(AuthenticationFailedError):
    """Псевдоним крипто-класса; сообщение не уточняется (см. выше)."""


class WeakPasswordError(VaultError):
    """Пароль не проходит минимальную проверку силы (без --i-know-its-weak)."""


class EntryNotFoundError(VaultError):
    """Запись с таким title не найдена."""


class VaultNotInitializedError(VaultError):
    """vault.enc отсутствует, а --init-if-missing не передан."""


class VaultAlreadyExistsError(VaultError):
    """vault.enc уже существует при попытке init."""


class ClipboardError(VaultError):
    """Не удалось скопировать/очистить буфер обмена."""
