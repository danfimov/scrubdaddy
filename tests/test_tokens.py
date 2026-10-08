import pytest

from scrubdaddy.models import Finding
from scrubdaddy.tokens import TokenMap


def finding(text: str, kind: str = "email") -> Finding:
    return Finding(beg=0, end=len(text), text=text, pii_type=kind, detector=kind)


@pytest.mark.parametrize(
    ("texts", "expected"),
    [
        (["a@b.io"], [0]),
        (["a@b.io", "a@b.io"], [0, 0]),
        (["a@b.io", "A@B.IO"], [0, 0]),
        (["a@b.io", "c@d.io", "a@b.io"], [0, 1, 0]),
    ],
)
def test_numbering_is_per_entity(texts, expected):
    tokens = TokenMap()
    assert [tokens.index_of(finding(text)) for text in texts] == expected


def test_numbering_is_counted_separately_per_kind():
    tokens = TokenMap()
    assert tokens.index_of(finding("a@b.io", "email")) == 0
    assert tokens.index_of(finding("+15551234567", "phone")) == 0


def test_numbering_continues_from_a_stored_map():
    first = TokenMap()
    first.index_of(finding("a@b.io"))
    second = TokenMap.from_dict(first.to_dict())
    assert second.index_of(finding("a@b.io")) == 0
    assert second.index_of(finding("c@d.io")) == 1


@pytest.mark.parametrize("keep_originals", [False, True])
def test_originals_are_kept_only_when_asked(keep_originals):
    tokens = TokenMap(keep_originals=keep_originals)
    tokens.remember("{{EMAIL-0}}", finding("a@b.io"))
    assert (tokens.original_of("{{EMAIL-0}}") == "a@b.io") is keep_originals


@pytest.mark.parametrize("include_originals", [False, True])
def test_serialisation_withholds_originals_by_default(include_originals):
    tokens = TokenMap(keep_originals=True)
    tokens.index_of(finding("a@b.io"))
    tokens.remember("{{EMAIL-0}}", finding("a@b.io"))
    payload = tokens.to_dict(include_originals=include_originals)
    assert ("originals" in payload) is include_originals
    assert "a@b.io" in tokens.to_json(include_originals=include_originals) or not include_originals


def test_custom_grouping_can_treat_variants_as_one_entity():
    tokens = TokenMap(group_key=lambda f: f.pii_type)
    assert tokens.index_of(finding("a@b.io")) == 0
    assert tokens.index_of(finding("c@d.io")) == 0
