import re
from typing import ClassVar

from scrubdaddy.detectors.base import RegexDetector
from scrubdaddy.models import PiiType
from scrubdaddy.validators import luhn

__all__ = ["CreditCardDetector"]


class CreditCardDetector(RegexDetector):
    """Finds payment card numbers.

    Digits may be grouped with single spaces or hyphens, the way cards are
    written down. The checksum is what keeps this from claiming every long
    number in a document.
    """

    name = "credit_card"
    pii_type = PiiType.CREDIT_CARD

    pattern: ClassVar[re.Pattern[str]] = re.compile(r"(?<![\w-])\d(?:[ -]?\d){11,18}(?![\w-])")

    _MIN_DIGITS = 13
    _MAX_DIGITS = 19

    def validate(self, text: str) -> bool:
        """Second opinion on a match, for checksums and blocklists."""
        digits = text.replace(" ", "").replace("-", "")
        if not self._MIN_DIGITS <= len(digits) <= self._MAX_DIGITS:
            return False
        return luhn(digits)
