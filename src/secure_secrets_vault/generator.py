"""Криптостойкая генерация паролей через модуль secrets (не random)."""

import secrets

LOWERS = "abcdefghijklmnopqrstuvwxyz"
UPPERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SPECIALS = "!@#$%^&*()-_=+[]{};:,.<>?"


def generate_password(
    length: int = 20,
    *,
    use_upper: bool = True,
    use_digits: bool = True,
    use_specials: bool = True,
    min_digits: int = 2,
    min_specials: int = 1,
) -> str:
    """Гарантированные минимумы цифр/спецсимволов, остальное — secrets.choice."""
    if length < 8:
        raise ValueError("length must be at least 8")
    pools: list[str] = [LOWERS]
    minimums: list[int] = [0]
    if use_upper:
        pools.append(UPPERS)
        minimums.append(0)
    if use_digits:
        pools.append(DIGITS)
        minimums.append(min_digits)
    if use_specials:
        pools.append(SPECIALS)
        minimums.append(min_specials)

    total_minimum = sum(minimums)
    if length < total_minimum:
        raise ValueError("length too small for requested minimums")

    chars: list[str] = []
    for pool, minimum in zip(pools, minimums, strict=True):
        chars.extend(secrets.choice(pool) for _ in range(minimum))
    all_chars = "".join(pools)
    while len(chars) < length:
        chars.append(secrets.choice(all_chars))
    # Фишер-Йейтс на secrets._urandom-базе: перемешиваем через secrets.sysrand
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words: int = 5, separator: str = "-") -> str:
    """Diceware-стиль на встроенном списке (короткий; для v1 достаточно)."""
    wordlist = _word_list()
    return separator.join(secrets.choice(wordlist) for _ in range(words))


def _word_list() -> tuple[str, ...]:
    return (
        "anchor", "brisk", "cactus", "dwell", "ember", "flint", "gravel",
        "harbor", "ivory", "jasper", "kelp", "lumen", "marble", "nectar",
        "onyx", "pixel", "quartz", "ripple", "slate", "tundra", "umber",
        "velvet", "willow", "xenon", "yonder", "zephyr", "basalt", "cobalt",
        "driftwood", "eclipse", "fathom", "glacier", "hazel", "inlet",
        "juniper", "karst", "lantern", "mesa", "nimbus", "obsidian",
    )
