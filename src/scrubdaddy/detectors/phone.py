from collections.abc import Iterator
from typing import ClassVar

import phonenumbers

from scrubdaddy.detectors.base import Detector
from scrubdaddy.locales import DEFAULT_LOCALE
from scrubdaddy.models import Finding, PiiType

__all__ = ["PhoneDetector"]


class PhoneDetector(Detector):
    """Finds telephone numbers.

    What counts as a number depends on the country, so the scrubber's region
    decides how loosely written ones are read. Accepting merely possible
    numbers catches more at the cost of precision, which is reflected in a
    lower confidence rather than hidden.
    """

    name = "phone"
    pii_type = PiiType.PHONE

    _SCORES: ClassVar[dict[str, float]] = {"valid": 1.0, "possible": 0.6}

    def __init__(
        self,
        locale: str = DEFAULT_LOCALE,
        score: float | None = None,
        leniency: str = "valid",
    ) -> None:
        if leniency not in self._SCORES:
            msg = f"leniency must be one of {sorted(self._SCORES)}, got {leniency!r}"
            raise ValueError(msg)
        super().__init__(locale=locale, score=self._SCORES[leniency] if score is None else score)
        self.leniency = leniency
        self._leniency = (
            phonenumbers.Leniency.VALID if leniency == "valid" else phonenumbers.Leniency.POSSIBLE
        )

    def find(self, text: str, document: str | None = None) -> Iterator[Finding]:
        """Scan one document."""
        for match in phonenumbers.PhoneNumberMatcher(text, self.region, leniency=self._leniency):
            yield self.finding(
                beg=match.start,
                end=match.end,
                text=match.raw_string,
                document=document,
            )
