import re
from collections.abc import Iterator
from typing import ClassVar

from scrubdaddy.detectors.base import RegexDetector
from scrubdaddy.models import Finding, PiiType

__all__ = ["UrlDetector"]


class UrlDetector(RegexDetector):
    """Finds web addresses, with a scheme or starting from a bare host."""

    name = "url"
    pii_type = PiiType.URL

    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        \b
        (?:
            (?:https?|ftps?|sftp)://[^\s<>"'`\]\[{}]{1,2048}
          | www\.[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,8}[^\s<>"'`\]\[{}]{0,2048}
        )
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    _TRAILING = ".,;:!?)]}>'\"`"

    def find(self, text: str, document: str | None = None) -> Iterator[Finding]:
        """Scan one document, giving sentence punctuation back to the sentence."""
        for finding in super().find(text, document=document):
            trimmed = finding.text.rstrip(self._TRAILING)
            if not trimmed:
                continue
            if len(trimmed) == len(finding.text):
                yield finding
            else:
                yield self.finding(
                    beg=finding.beg,
                    end=finding.beg + len(trimmed),
                    text=trimmed,
                    document=document,
                    score=finding.score,
                )
