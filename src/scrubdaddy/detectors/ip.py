import ipaddress
import re
from collections.abc import Iterator
from typing import ClassVar

from scrubdaddy.detectors.base import Detector
from scrubdaddy.models import Finding, PiiType

__all__ = ["IpDetector"]


class IpDetector(Detector):
    """Finds IPv4 and IPv6 addresses.

    Candidates come from a cheap pattern and are confirmed by the standard
    library, which is both stricter and far easier to trust than a regular
    expression that tries to express the whole address grammar.
    """

    name = "ip"
    pii_type = PiiType.IP

    _IPV4: ClassVar[re.Pattern[str]] = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
    _IPV6: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])",
        re.IGNORECASE,
    )

    def find(self, text: str, document: str | None = None) -> Iterator[Finding]:
        """Scan one document."""
        for pattern, version in ((self._IPV4, "4"), (self._IPV6, "6")):
            for match in pattern.finditer(text):
                candidate = match.group()
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                yield self.finding(
                    beg=match.start(),
                    end=match.end(),
                    text=candidate,
                    document=document,
                    context={"version": version},
                )
