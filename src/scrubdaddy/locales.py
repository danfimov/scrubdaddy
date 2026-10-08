import re

__all__ = ["DEFAULT_LOCALE", "matches_locale", "parse_locale"]

DEFAULT_LOCALE = "en_US"

_LOCALE_RE = re.compile(r"^([a-z]{2,3})[_-]([A-Za-z]{2})$")


def parse_locale(locale: str) -> tuple[str, str]:
    """Split a POSIX-style locale into its language and region parts.

    >>> parse_locale("ru_RU")
    ('ru', 'RU')
    """
    match = _LOCALE_RE.match(locale.strip())
    if match is None:
        msg = f"locale {locale!r} is not in the expected 'xx_XX' format"
        raise ValueError(msg)
    language, region = match.groups()
    return language.lower(), region.upper()


def matches_locale(locale: str, supported: frozenset[str] | None) -> bool:
    """Whether a locale is covered by a set of supported ones.

    Support can be declared per region ("en_GB") or for a whole language
    ("en"), because some identifiers are national and others are not. An empty
    declaration means the detector does not care about the locale at all.
    """
    if supported is None:
        return True
    language, region = parse_locale(locale)
    return f"{language}_{region}" in supported or language in supported
