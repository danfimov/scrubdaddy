import pytest

from scrubdaddy.models import Finding
from scrubdaddy.resolve import Strategy, resolve


def finding(
    beg: int,
    end: int,
    kind: str = "email",
    detector: str | None = None,
    score: float = 1.0,
) -> Finding:
    return Finding(
        beg=beg,
        end=end,
        text="x" * (end - beg),
        pii_type=kind,
        detector=detector or kind,
        score=score,
    )


@pytest.mark.parametrize("strategy", list(Strategy))
def test_empty_input(strategy):
    assert resolve([], strategy=strategy) == []


@pytest.mark.parametrize("strategy", list(Strategy))
def test_output_is_ordered_by_position(strategy):
    findings = [finding(20, 25), finding(0, 5), finding(10, 15)]
    assert [f.beg for f in resolve(findings, strategy=strategy)] == [0, 10, 20]


@pytest.mark.parametrize(
    ("strategy", "expected"),
    [
        (Strategy.HIGHEST_SCORE, [(0, 4)]),
        (Strategy.LONGEST, [(0, 10)]),
    ],
)
def test_score_and_length_pull_in_different_directions(strategy, expected):
    findings = [finding(0, 10, score=0.5, detector="weak"), finding(0, 4, score=0.9, detector="strong")]
    assert [(f.beg, f.end) for f in resolve(findings, strategy=strategy)] == expected


@pytest.mark.parametrize(
    ("strategy", "count"),
    [
        (Strategy.HIGHEST_SCORE, 1),
        (Strategy.LONGEST, 1),
        (Strategy.MERGE, 1),
        (Strategy.KEEP_ALL, 2),
    ],
)
def test_overlaps_are_settled_except_when_auditing(strategy, count):
    findings = [finding(0, 6, kind="name"), finding(4, 10, kind="email")]
    assert len(resolve(findings, strategy=strategy)) == count


def test_merge_spans_the_whole_cluster():
    merged = resolve(
        [finding(0, 6, kind="name"), finding(4, 10, kind="email")],
        strategy=Strategy.MERGE,
    )
    assert [(f.beg, f.end) for f in merged] == [(0, 10)]
    assert merged[0].pii_type == "email+name"
    assert len(merged[0].text) == 10


def test_touching_findings_are_left_separate():
    resolved = resolve([finding(0, 5, kind="name"), finding(5, 10, kind="email")], strategy=Strategy.MERGE)
    assert [(f.beg, f.end) for f in resolved] == [(0, 5), (5, 10)]


def test_a_discarded_long_match_does_not_hide_short_ones():
    findings = [
        finding(0, 30, score=0.4, detector="weak"),
        finding(0, 5, score=0.9, detector="strong"),
        finding(20, 25, score=0.9, detector="strong"),
    ]
    assert [(f.beg, f.end) for f in resolve(findings)] == [(0, 5), (20, 25)]


@pytest.mark.parametrize(
    ("priority", "winner"),
    [
        ({"a": 1, "b": 0}, "a"),
        ({"a": 0, "b": 1}, "b"),
    ],
)
def test_priority_breaks_ties(priority, winner):
    findings = [finding(0, 5, detector="a", score=0.5), finding(0, 5, detector="b", score=0.5)]
    resolved = resolve(findings, priority=priority)
    assert [f.detector for f in resolved] == [winner]
