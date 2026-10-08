import re
from typing import ClassVar

from scrubdaddy.detectors.base import RegexDetector
from scrubdaddy.models import PiiType

__all__ = ["UuidDetector"]


class UuidDetector(RegexDetector):
    """Finds identifiers in the canonical hyphenated form.

    Such an identifier is not personal data in itself, but it is very often the
    user key in a log line, which is why it stays out of the default set.
    """

    name = "uuid"
    pii_type = PiiType.UUID

    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])",
        re.IGNORECASE,
    )
