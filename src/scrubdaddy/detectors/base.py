import abc
import re
from collections.abc import Iterator, Mapping, Sequence
from typing import ClassVar

from scrubdaddy.locales import DEFAULT_LOCALE, parse_locale
from scrubdaddy.models import Finding

__all__ = ["Detector", "RegexDetector"]


class Detector(abc.ABC):
    """Finds one kind of personal data in text.

    Everything a detector needs arrives in the constructor and nothing is kept
    on the class, so one instance is safe to reuse across documents, scrubbers
    and threads.
    """

    name: ClassVar[str]
    pii_type: ClassVar[str]
    locales: ClassVar[frozenset[str] | None] = None
    default_score: ClassVar[float] = 1.0

    def __init__(self, locale: str = DEFAULT_LOCALE, score: float | None = None) -> None:
        self.locale = locale
        self.language, self.region = parse_locale(locale)
        self.score = self.default_score if score is None else score
        if not 0.0 <= self.score <= 1.0:
            msg = f"score must be within [0.0, 1.0], got {self.score}"
            raise ValueError(msg)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r} locale={self.locale!r} score={self.score:.2f}>"

    @abc.abstractmethod
    def find(self, text: str, document: str | None = None) -> Iterator[Finding]:
        """Scan one document."""

    def find_batch(self, texts: Sequence[str], documents: Sequence[str | None]) -> Iterator[Finding]:
        """Scan several documents at once.

        Worth overriding only for models that are much faster in batches. The
        default simply loops, so a scrubber never has to ask whether a detector
        supports batching.
        """
        for text, document in zip(texts, documents, strict=True):
            yield from self.find(text, document=document)

    def finding(  # noqa: PLR0913  # metadata of one match, named at every call site
        self,
        beg: int,
        end: int,
        text: str,
        document: str | None = None,
        score: float | None = None,
        pii_type: str | None = None,
        context: Mapping[str, str] | None = None,
    ) -> Finding:
        """Stamp a match with this detector's identity."""
        return Finding(
            beg=beg,
            end=end,
            text=text,
            pii_type=pii_type or self.pii_type,
            detector=self.name,
            score=self.score if score is None else score,
            locale=self.locale,
            document=document,
            context=context or {},
        )


class RegexDetector(Detector):
    """Finds personal data with a regular expression.

    Patterns are expected to be free of nested unbounded quantifiers so that
    they stay linear on hostile input; the test suite holds every registered
    pattern to that. Pointing at a capturing group keeps surrounding context
    out of the match, so a label such as the word "password" survives the
    replacement while its value does not.
    """

    pattern: ClassVar[re.Pattern[str]]
    group: ClassVar[str | None] = None

    def find(self, text: str, document: str | None = None) -> Iterator[Finding]:
        """Scan one document."""
        for match in self.pattern.finditer(text):
            beg, end = match.span(self.group) if self.group is not None else match.span()
            if beg < 0 or beg >= end:
                # An optional group that did not take part in the match.
                continue
            matched = text[beg:end]
            if not self.validate(matched):
                continue
            yield self.finding(
                beg=beg,
                end=end,
                text=matched,
                document=document,
                score=self.score_for(matched),
            )

    def validate(self, text: str) -> bool:
        """Second opinion on a match, for checksums and blocklists."""
        del text
        return True

    def score_for(self, text: str) -> float:
        """Confidence in one particular match, when some are weaker than others."""
        del text
        return self.score
