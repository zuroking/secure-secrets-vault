"""Встроенный статический список самых частых утёкших паролей.

Без сетевых запросов (скоуп §1: no network). Представительный top-list;
структура допускает замену на полный датасет без изменения API.
"""

COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456", "password", "123456789", "12345678", "12345", "qwerty",
        "1234567890", "1234567", "111111", "123123", "abc123", "1234",
        "password1", "iloveyou", "000000", "qwerty123", "1q2w3e4r",
        "admin", "qwertyuiop", "654321", "555555", "lovely", "7777777",
        "888888", "princess", "dragon", "sunshine", "master", "monkey",
        "shadow", "football", "baseball", "letmein", "welcome", "login",
        "solo", "flower", "hottie", "loveme", "zaq12wsx", "password123",
        "trustno1", "batman", "superman", "michael", "jennifer", "hunter",
        "tigger", "soccer", "harley", "ranger", "buster", "thomas",
        "robert", "soccer1", "jordan23", "hello", "freedom", "whatever",
        "qazwsx", "google", "computer", "secret", "starwars", "passw0rd",
        "p@ssw0rd", "changeme", "default", "administrator", "root",
        "toor", "test", "guest", "master1", "asdfgh", "zxcvbnm",
        "1qaz2wsx", "qwerty1", "a123456", "123qwe", "aa123456789",
        "qwe123", "1q2w3e", "121212", "159753", "987654321", "102030",
        "112233", "123321", "696969", "666666", "asdf", "asdasd",
        "internet", "service", "canada", "hello123", "ranger1",
    }
)
