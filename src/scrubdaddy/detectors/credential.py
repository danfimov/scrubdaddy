import re
from typing import ClassVar

from scrubdaddy.detectors.base import RegexDetector
from scrubdaddy.models import PiiType

__all__ = ["PasswordDetector"]


class PasswordDetector(RegexDetector):
    """Finds the value that follows a password-like label.

    Only the value is reported, so the text stays readable afterwards. Looking
    for the label alone, rather than for a username and a password together,
    also catches the two when they are far apart or in the opposite order.
    """

    name = "password"
    pii_type = PiiType.CREDENTIAL
    group = "secret"

    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        \b(?:password|passwd|pwd|pass|secret|api[_-]?key|token|auth)\b
        [\t ]*[:=][\t ]*
        (?P<quote>["']?)
        (?P<secret>[^\s"']{1,256})
        (?P=quote)
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    _PLACEHOLDERS: ClassVar[frozenset[str]] = frozenset({
        "none",
        "null",
        "nil",
        "true",
        "false",
        "redacted",
        "hidden",
        "changeme",
        "example",
        "xxx",
        "***",
    })

    def validate(self, text: str) -> bool:
        """Leave obvious placeholders alone, so config templates stay legible."""
        return text.lower() not in self._PLACEHOLDERS
