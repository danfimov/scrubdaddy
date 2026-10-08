import pytest

from scrubdaddy.models import Finding


def make(**kwargs: object) -> Finding:
    defaults: dict[str, object] = {"beg": 0, "end": 5, "text": "hello", "pii_type": "email",
                                   "detector": "email"}
    return Finding(**{**defaults, **kwargs})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"beg": -1, "end": 4, "text": "abcd"}, "negative start"),
        ({"beg": 5, "end": 5, "text": ""}, "empty span"),
        ({"beg": 7, "end": 3, "text": "abcd"}, "inverted span"),
        ({"beg": 0, "end": 4, "text": "abcde"}, "text longer than span"),
        ({"beg": 0, "end": 5, "text": "abcd"}, "text shorter than span"),
        ({"score": 1.5}, "score above one"),
        ({"score": -0.1}, "score below zero"),
        ({"pii_type": ""}, "missing kind"),
        ({"detector": ""}, "missing detector"),
    ],
)
def test_rejects_impossible_findings(kwargs, reason):
    with pytest.raises(ValueError, match=r".") as caught:
        make(**kwargs)
    assert reason  # the parametrisation label documents the case
    assert "hello" not in str(caught.value), "detected text must not reach the message"


@pytest.mark.parametrize(
    ("first", "second", "overlaps"),
    [
        ((0, 5), (3, 8), True),
        ((3, 8), (0, 5), True),
        ((0, 5), (0, 5), True),
        ((0, 10), (3, 5), True),
        ((0, 5), (5, 10), False),
        ((5, 10), (0, 5), False),
        ((0, 5), (6, 10), False),
    ],
)
def test_overlap_excludes_touching_spans(first, second, overlaps):
    left = make(beg=first[0], end=first[1], text="x" * (first[1] - first[0]))
    right = make(beg=second[0], end=second[1], text="x" * (second[1] - second[0]))
    assert left.overlaps(right) is overlaps


@pytest.mark.parametrize("offset", [0, 1, 100])
def test_shift_moves_span_only(offset):
    finding = make()
    moved = finding.shift(offset)
    assert (moved.beg, moved.end) == (finding.beg + offset, finding.end + offset)
    assert moved.text == finding.text
    assert len(moved) == len(finding)


def test_context_does_not_affect_identity():
    assert make(context={"kind": "a"}) == make(context={"kind": "b"})
    assert len({make(context={"kind": "a"}), make(context={"kind": "b"})}) == 1


@pytest.mark.parametrize("include_text", [False, True])
def test_serialisation_withholds_text_by_default(include_text):
    payload = make(context={"kind": "work"}).to_dict(include_text=include_text)
    assert ("text" in payload) is include_text
    assert payload["context"] == {"kind": "work"}


def test_repr_hides_detected_text():
    assert "hello" not in repr(make())
