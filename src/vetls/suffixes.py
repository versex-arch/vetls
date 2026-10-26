"""A small built-in list of public suffixes.

Used to reject certificates with wildcards such as ``*.com`` or ``*.co.uk``.
This is a conservative static subset, not the full Public Suffix List; see
the "Limitations" section of the README.
"""

from __future__ import annotations

PUBLIC_SUFFIXES = frozenset(
    {
        # generic
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        "info",
        "biz",
        "name",
        "io",
        "co",
        "ai",
        "app",
        "dev",
        "xyz",
        "online",
        "site",
        "tech",
        "cloud",
        # country codes that are commonly used as flat suffixes
        "de",
        "fr",
        "nl",
        "ru",
        "pl",
        "it",
        "es",
        "se",
        "no",
        "fi",
        "dk",
        "ch",
        "at",
        "be",
        "cz",
        "ua",
        "kz",
        "us",
        "ca",
        "uk",
        "au",
        "nz",
        "jp",
        "cn",
        "in",
        "br",
        "mx",
        "ar",
        "kr",
        "tr",
        "za",
        "eu",
        # common second-level suffixes
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "me.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "co.nz",
        "org.nz",
        "net.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "com.br",
        "net.br",
        "org.br",
        "com.cn",
        "net.cn",
        "org.cn",
        "co.in",
        "net.in",
        "org.in",
        "co.za",
        "org.za",
        "com.mx",
        "com.ar",
        "com.tr",
        "com.ua",
        "com.kz",
        "org.kz",
        "co.kr",
        "or.kr",
    }
)


def is_public_suffix(name: str) -> bool:
    """Return True if ``name`` is (case-insensitively) a known public suffix."""
    return name.lower().strip(".") in PUBLIC_SUFFIXES
