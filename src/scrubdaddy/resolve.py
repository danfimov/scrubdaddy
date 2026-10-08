from collections.abc import Iterator, Mapping, Sequence
from enum import StrEnum

from scrubdaddy.models import Finding

__all__ = ["Strategy", "resolve"]


class Strategy(StrEnum):
    """How to settle two detectors claiming overlapping text.

    Only one of these can be right for a given purpose, so the choice belongs
    to the caller rather than to the library.
    """

    HIGHEST_SCORE = "highest_score"
    LONGEST = "longest"
    MERGE = "merge"
    KEEP_ALL = "keep_all"


def _sorted(findings: Sequence[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.beg, -f.end))


def _clusters(findings: Sequence[Finding]) -> Iterator[list[Finding]]:
    """Walk groups of findings that are connected by overlap.

    Working cluster by cluster keeps the comparison between competing findings
    local, so a document with many findings stays cheap to resolve.
    """
    cluster: list[Finding] = []
    reach = -1
    for finding in _sorted(findings):
        if cluster and finding.beg >= reach:
            yield cluster
            cluster = []
        cluster.append(finding)
        reach = max(reach, finding.end)
    if cluster:
        yield cluster


def _pick(
    cluster: Sequence[Finding],
    strategy: Strategy,
    priority: Mapping[str, int],
) -> list[Finding]:
    """Choose the winners inside one cluster.

    A finding that loses to the winner but does not overlap it is kept, so that
    discarding a long weak match cannot hide two short strong ones.
    """
    if strategy is Strategy.MERGE:
        return [_merge(cluster)]

    def rank(finding: Finding) -> tuple[float, float, int, int]:
        weight = priority.get(finding.detector, 0)
        if strategy is Strategy.LONGEST:
            return (len(finding), finding.score, weight, -finding.beg)
        return (finding.score, len(finding), weight, -finding.beg)

    accepted: list[Finding] = []
    for finding in sorted(cluster, key=rank, reverse=True):
        if not any(finding.overlaps(other) for other in accepted):
            accepted.append(finding)
    return accepted


def _merge(cluster: Sequence[Finding]) -> Finding:
    """Fuse a cluster into one finding covering all of it."""
    first = min(cluster, key=lambda f: f.beg)
    beg = first.beg
    end = max(f.end for f in cluster)
    kinds = sorted({f.pii_type for f in cluster})
    detectors = sorted({f.detector for f in cluster})
    # The pieces may not cover the span continuously, so the text is taken from
    # the finding that starts first and extended by the ones reaching furthest.
    text = first.text
    for finding in _sorted(cluster):
        if finding.end > beg + len(text):
            text += finding.text[-(finding.end - beg - len(text)) :]
    return Finding(
        beg=beg,
        end=end,
        text=text,
        pii_type="+".join(kinds),
        detector="+".join(detectors),
        score=max(f.score for f in cluster),
        locale=first.locale,
        document=first.document,
        context={"merged": str(len(cluster))},
    )


def resolve(
    findings: Sequence[Finding],
    strategy: Strategy = Strategy.HIGHEST_SCORE,
    priority: Mapping[str, int] | None = None,
) -> list[Finding]:
    """Turn possibly overlapping findings into an ordered, disjoint list.

    Replacement needs disjoint spans; auditing does not, which is what the
    keep-all strategy is for. Named detectors can be given a weight to break
    ties between findings that are otherwise equally convincing.
    """
    if not findings:
        return []
    if strategy is Strategy.KEEP_ALL:
        return _sorted(findings)

    weights = priority or {}
    resolved: list[Finding] = []
    for cluster in _clusters(findings):
        if len(cluster) == 1:
            resolved.extend(cluster)
        else:
            resolved.extend(_pick(cluster, strategy=strategy, priority=weights))
    return _sorted(resolved)
