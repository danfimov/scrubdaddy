import re
from typing import ClassVar

from scrubdaddy.detectors.base import RegexDetector
from scrubdaddy.models import PiiType
from scrubdaddy.validators import mod97

__all__ = ["IbanDetector"]


class IbanDetector(RegexDetector):
    """Finds international bank account numbers."""

    name = "iban"
    pii_type = PiiType.IBAN

    # Case-sensitive on purpose: letting lower case in makes the trailing
    # groups indistinguishable from the next word in a sentence.
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){2,8}(?![A-Za-z0-9])",
    )

    def validate(self, text: str) -> bool:
        """Second opinion on a match, for checksums and blocklists."""
        return mod97(text)
