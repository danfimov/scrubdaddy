import pytest

from scrubdaddy.models import Finding
from scrubdaddy.render import Mask, Remove, Token
from scrubdaddy.tokens import TokenMap


def finding(text: str = "joe@example.com", kind: str = "email") -> Finding:
    return Finding(beg=0, end=len(text), text=text, pii_type=kind, detector=kind)


@pytest.mark.parametrize(
    ("renderer", "expected"),
    [
        (Token(), "{{EMAIL}}"),
        (Token(uppercase=False), "{{email}}"),
        (Token(prefix="<", suffix=">"), "<EMAIL>"),
        (Token(include_count=True), "{{EMAIL-0}}"),
        (Token(include_kind=False, include_count=True), "{{0}}"),
        (Remove(), ""),
        (Mask(), "***************"),
        (Mask(char="#"), "###############"),
        (Mask(keep_last=4), "***********.com"),
        (Mask(fixed_length=5), "*****"),
    ],
)
def test_rendering(renderer, expected):
    assert renderer.render(finding(), TokenMap()) == expected


@pytest.mark.parametrize(
    "kwargs",
    [
        {"include_kind": False},
        {"include_hash": True},
        {"include_hash": True, "salt": None},
        {"hash_length": 0, "include_hash": True, "salt": "s"},
    ],
)
def test_token_rejects_configurations_that_would_mislead(kwargs):
    with pytest.raises(ValueError, match=r"."):
        Token(**kwargs)


@pytest.mark.parametrize("kwargs", [{"char": "ab"}, {"char": ""}, {"keep_last": -1}, {"fixed_length": 0}])
def test_mask_rejects_impossible_configurations(kwargs):
    with pytest.raises(ValueError, match=r"."):
        Mask(**kwargs)


def test_hash_is_stable_for_the_same_salt_and_differs_across_salts():
    one = Token(include_hash=True, salt="pepper").render(finding(), TokenMap())
    again = Token(include_hash=True, salt="pepper").render(finding(), TokenMap())
    other = Token(include_hash=True, salt="other").render(finding(), TokenMap())
    assert one == again
    assert one != other


def test_hash_ignores_case_so_one_entity_gets_one_token():
    upper = Token(include_hash=True, salt="pepper").render(finding("JOE@EXAMPLE.COM"), TokenMap())
    lower = Token(include_hash=True, salt="pepper").render(finding("joe@example.com"), TokenMap())
    assert upper == lower


@pytest.mark.parametrize("length", [4, 8, 16])
def test_hash_length(length):
    rendered = Token(include_kind=False, include_hash=True, salt="s", hash_length=length).render(
        finding(), TokenMap(),
    )
    assert len(rendered) == len("{{}}") + length
