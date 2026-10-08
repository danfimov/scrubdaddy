import pytest

from scrubdaddy.detectors.phone import PhoneDetector


def found(text: str, locale: str = "en_US", leniency: str = "valid") -> list[str]:
    detector = PhoneDetector(locale=locale, leniency=leniency)
    return [f.text for f in detector.find(text)]


@pytest.mark.parametrize(
    ("locale", "text", "expected"),
    [
        ("en_US", "call (212) 555-0199 now", ["(212) 555-0199"]),
        ("en_US", "call +44 20 7183 8750 now", ["+44 20 7183 8750"]),
        ("en_GB", "call 020 7183 8750 now", ["020 7183 8750"]),
        ("en_US", "call 020 7183 8750 now", []),
        ("en_US", "order 12345 shipped", []),
    ],
)
def test_the_region_decides_how_loose_numbers_are_read(locale, text, expected):
    assert found(text, locale=locale) == expected


@pytest.mark.parametrize(
    ("leniency", "score"),
    [
        ("valid", 1.0),
        ("possible", 0.6),
    ],
)
def test_leniency_is_reflected_in_the_confidence(leniency, score):
    detector = PhoneDetector(leniency=leniency)
    assert detector.score == score


def test_being_lenient_finds_more_at_a_lower_confidence():
    text = "ref 5550199"
    assert found(text) == []
    lenient = list(PhoneDetector(leniency="possible").find(text))
    assert [f.score for f in lenient] == [0.6]


def test_unknown_leniency_is_refused():
    with pytest.raises(ValueError, match="leniency must be one of"):
        PhoneDetector(leniency="maybe")


def test_an_explicit_score_wins_over_the_leniency_default():
    assert PhoneDetector(leniency="possible", score=0.9).score == 0.9
