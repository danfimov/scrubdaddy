import re
from typing import ClassVar

from scrubdaddy.detectors.base import RegexDetector
from scrubdaddy.models import PiiType

__all__ = ["EmailDetector"]


class EmailDetector(RegexDetector):
    """Finds email addresses."""

    name = "email"
    pii_type = PiiType.EMAIL

    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        (?<![\w.+-])
        [a-z0-9!#$%'*+^_`{|}~-]
        (?:[a-z0-9.!#$%'*+^_`{|}~-]{0,62}[a-z0-9!#$%'*+^_`{|}~-])?
        @
        [a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?
        (?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,8}
        (?![\w-])
        """,
        re.IGNORECASE | re.VERBOSE,
    )
