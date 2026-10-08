from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Self

__all__ = ["Finding", "PiiType"]


class PiiType:
    """Names of the kinds of personal data scrubdaddy ships detectors for.

    Plain strings rather than an enum, so that a third-party detector can
    introduce its own kind without patching this class.
    """

    CREDENTIAL = "credential"
    CREDIT_CARD = "credit_card"
    DATE_OF_BIRTH = "date_of_birth"
    EMAIL = "email"
    IBAN = "iban"
    IP = "ip"
    NAME = "name"
    PHONE = "phone"
    POSTAL_CODE = "postal_code"
    SECRET = "secret"  # noqa: S105  # the name of a kind of data, not a credential
    URL = "url"
    UUID = "uuid"


@dataclass(frozen=True, slots=True)
class Finding:
    """A single piece of personal data located in a document.

    The span is half-open, so slicing a document by it gives back exactly the
    matched text. Confidence is carried on every finding rather than implied,
    which is what lets several detectors disagree and still be combined.

    Detector notes stay out of equality and hashing, so two findings that agree
    on the span are not treated as different because one of them happens to
    carry extra debug information.
    """

    beg: int
    end: int
    text: str
    pii_type: str
    detector: str
    score: float = 1.0
    locale: str | None = None
    document: str | None = None
    context: Mapping[str, str] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        # Offsets and lengths only: the matched text must not reach a traceback.
        if self.beg < 0:
            msg = f"finding starts at {self.beg}, must not be negative"
            raise ValueError(msg)
        if self.beg >= self.end:
            msg = f"finding is empty or inverted: [{self.beg}, {self.end})"
            raise ValueError(msg)
        if len(self.text) != self.end - self.beg:
            msg = f"text length {len(self.text)} does not match span [{self.beg}, {self.end})"
            raise ValueError(msg)
        if not 0.0 <= self.score <= 1.0:
            msg = f"score must be within [0.0, 1.0], got {self.score}"
            raise ValueError(msg)
        if not self.pii_type:
            msg = "pii_type must not be empty"
            raise ValueError(msg)
        if not self.detector:
            msg = "detector must not be empty"
            raise ValueError(msg)

    def __len__(self) -> int:
        return self.end - self.beg

    def __repr__(self) -> str:
        # The matched text is personal data, so it is left out on purpose.
        document = f" document={self.document!r}" if self.document is not None else ""
        return (
            f"<Finding {self.pii_type} [{self.beg}:{self.end}] len={len(self)} "
            f"score={self.score:.2f} detector={self.detector!r}{document}>"
        )

    def overlaps(self, other: "Finding") -> bool:
        """Whether the two spans share at least one character.

        Spans that merely touch do not count, so neighbouring findings of
        different kinds are never glued into one replacement.
        """
        return self.beg < other.end and other.beg < self.end

    def shift(self, offset: int) -> Self:
        """Move the span, for when a detector ran on a slice of a document."""
        return type(self)(
            beg=self.beg + offset,
            end=self.end + offset,
            text=self.text,
            pii_type=self.pii_type,
            detector=self.detector,
            score=self.score,
            locale=self.locale,
            document=self.document,
            context=self.context,
        )

    def to_dict(self, include_text: bool = False) -> dict[str, Any]:
        """Render for an audit trail.

        The matched text is omitted unless asked for, because the usual reason
        to serialise findings is to keep a record somewhere less protected than
        the document itself.
        """
        payload: dict[str, Any] = {
            "beg": self.beg,
            "end": self.end,
            "pii_type": self.pii_type,
            "detector": self.detector,
            "score": self.score,
        }
        if self.locale is not None:
            payload["locale"] = self.locale
        if self.document is not None:
            payload["document"] = self.document
        if self.context:
            payload["context"] = dict(self.context)
        if include_text:
            payload["text"] = self.text
        return payload
