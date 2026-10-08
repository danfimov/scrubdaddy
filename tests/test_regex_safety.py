import re
import time

import pytest

from scrubdaddy.detectors import default_registry

# A pattern that backtracks badly is a denial of service, because these run on
# text that arrives from outside. The budget is generous: a linear pattern
# finishes these in single-digit milliseconds, while a pattern with nested
# unbounded quantifiers needs far longer than a second.
BUDGET_SECONDS = 0.5
LENGTH = 20_000

HOSTILE = {
    "letters": "a" * LENGTH,
    "digits": "9" * LENGTH,
    "spaces": " " * LENGTH,
    "digits_and_spaces": "9 " * (LENGTH // 2),
    "dashes": "-" * LENGTH,
    "dots": "." * LENGTH,
    "at_signs": "@" * LENGTH,
    "digits_then_letter": "9" * LENGTH + "x",
    "letters_then_at": "a" * LENGTH + "@",
    "digits_spaces_then_letter": "9 " * (LENGTH // 2) + "x",
    "upper_and_spaces": "A " * (LENGTH // 2),
    "iban_prefix": "GB82" + "AB12 " * (LENGTH // 5),
    "key_prefix": "sk-" + "a" * LENGTH,
    "jwt_prefix": "eyJ" + "a" * LENGTH,
    "begin_block": "-----BEGIN " + "AAAA " * (LENGTH // 5),
    "scheme_prefix": "https://" + "a:" * (LENGTH // 2),
    "label_then_value": "password:" + "a" * LENGTH,
    "colons": ":" * LENGTH,
    "hex_and_colons": "abcd:" * (LENGTH // 5),
    # Digits inside runs of whitespace are what actually breaks a pattern like
    # (?:\\s*\\d\\s*){6}: the whitespace can be split between iterations in
    # exponentially many ways. CANARY below shows this corpus has teeth.
    "digits_in_space_runs": ("9" + " " * 20) * 40 + "!",
    "letters_then_digits_in_space_runs": "AAAAA" + ("9" + " " * 20) * 40 + "!",
    "alnum_in_space_runs": ("A9" + " " * 18) * 40 + "!",
}

# The pattern that scrubadub still ships for UK driving licences, kept here as
# a canary: if the corpus above ever stops catching it, the budget test has
# quietly stopped protecting anything.
CANARY = re.compile(r"([a-zA-Z9]{5}\s?)((?:\s*\d\s*){6}[a-zA-Z9]{2}\w{3})\s?(\d{2})", re.IGNORECASE)


def shipped_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """Every pattern a shipped detector would run, named for the test report."""
    registry = default_registry()
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for entry in registry:
        try:
            detector = registry.load(entry.name)
        except ImportError:  # an optional dependency is not installed here
            continue
        single = getattr(detector, "pattern", None)
        if isinstance(single, re.Pattern):
            patterns.append((entry.name, single))
        for kind, pattern in getattr(detector, "patterns", {}).items():
            patterns.append((f"{entry.name}.{kind}", pattern))
    return patterns


PATTERNS = shipped_patterns()


def test_patterns_were_discovered():
    assert len(PATTERNS) >= 9


def test_the_budget_test_can_actually_fail():
    slowest = 0.0
    for hostile in HOSTILE.values():
        started = time.perf_counter()
        CANARY.search(hostile[:120])
        slowest = max(slowest, time.perf_counter() - started)
    assert slowest > BUDGET_SECONDS, "the hostile corpus no longer provokes a known-bad pattern"


@pytest.mark.parametrize(("name", "pattern"), PATTERNS, ids=[name for name, _ in PATTERNS])
@pytest.mark.parametrize("hostile", HOSTILE.values(), ids=list(HOSTILE))
def test_patterns_stay_fast_on_hostile_input(name, pattern, hostile):
    started = time.perf_counter()
    pattern.findall(hostile)
    elapsed = time.perf_counter() - started
    assert elapsed < BUDGET_SECONDS, f"{name} took {elapsed:.3f}s on {len(hostile)} characters"
