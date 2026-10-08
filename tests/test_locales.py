import pytest

from scrubdaddy.locales import matches_locale, parse_locale


@pytest.mark.parametrize(
    ("locale", "expected"),
    [
        ("en_US", ("en", "US")),
        ("ru_RU", ("ru", "RU")),
        ("en-GB", ("en", "GB")),
        ("en_gb", ("en", "GB")),
        (" de_CH ", ("de", "CH")),
    ],
)
def test_parse(locale, expected):
    assert parse_locale(locale) == expected


@pytest.mark.parametrize("locale", ["en", "english_US", "e_US", "en_USA", ""])
def test_parse_rejects_malformed(locale):
    with pytest.raises(ValueError, match="expected"):
        parse_locale(locale)


@pytest.mark.parametrize(
    ("locale", "supported", "matches"),
    [
        ("en_US", None, True),
        ("en_US", frozenset({"en_US"}), True),
        ("en_US", frozenset({"en"}), True),
        ("en_GB", frozenset({"en_US"}), False),
        ("ru_RU", frozenset({"en", "de"}), False),
    ],
)
def test_matching(locale, supported, matches):
    assert matches_locale(locale, supported) is matches
