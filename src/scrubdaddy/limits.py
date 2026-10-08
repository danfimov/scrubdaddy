from dataclasses import dataclass

from scrubdaddy.exceptions import LimitExceededError

__all__ = ["Limits"]


@dataclass(frozen=True, slots=True)
class Limits:
    """Bounds for a single scrub call.

    Detectors are assumed to run on untrusted input, so the amount of work one
    call can trigger is capped explicitly rather than by convention.
    """

    max_chars: int = 10_000_000
    max_total_chars: int = 100_000_000
    max_findings: int = 1_000_000

    def __post_init__(self) -> None:
        for name in ("max_chars", "max_total_chars", "max_findings"):
            value: int = getattr(self, name)
            if value <= 0:
                msg = f"{name} must be positive, got {value}"
                raise ValueError(msg)

    def check_document(self, length: int, document: str | None = None) -> None:
        """Guard a single document."""
        if length > self.max_chars:
            what = "input length" if document is None else f"length of document {document!r}"
            raise LimitExceededError(what=what, actual=length, limit=self.max_chars)

    def check_total(self, length: int) -> None:
        """Guard the combined size of all documents."""
        if length > self.max_total_chars:
            raise LimitExceededError(what="total input length", actual=length, limit=self.max_total_chars)

    def check_findings(self, count: int) -> None:
        """Guard against pathological inputs that match almost everywhere."""
        if count > self.max_findings:
            raise LimitExceededError(what="number of findings", actual=count, limit=self.max_findings)
