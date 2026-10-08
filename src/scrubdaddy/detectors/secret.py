import re
from collections.abc import Iterator
from typing import ClassVar

from scrubdaddy.detectors.base import Detector
from scrubdaddy.models import Finding, PiiType

__all__ = ["SecretDetector"]


class SecretDetector(Detector):
    """Finds keys and tokens issued by well-known services.

    This is the class of secret that actually turns up in logs, config dumps
    and support tickets, and providers give them distinctive prefixes, so it
    can be detected precisely rather than guessed at. Which kind matched is
    reported alongside the finding, which is what a leak triage needs first.
    """

    name = "secret"
    pii_type = PiiType.SECRET

    patterns: ClassVar[dict[str, re.Pattern[str]]] = {
        "aws_access_key": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Z0-9])"),
        "github_token": re.compile(r"(?<![\w-])gh[pousr]_[A-Za-z0-9]{36,251}(?![\w-])"),
        "slack_token": re.compile(r"(?<![\w-])xox[baprs]-[A-Za-z0-9-]{10,250}(?![\w-])"),
        "anthropic_key": re.compile(r"(?<![\w-])sk-ant-[A-Za-z0-9_-]{20,250}(?![\w-])"),
        "openai_key": re.compile(r"(?<![\w-])sk-(?:proj-)?[A-Za-z0-9_-]{20,250}(?![\w-])"),
        "google_api_key": re.compile(r"(?<![\w-])AIza[0-9A-Za-z_-]{35}(?![\w-])"),
        "jwt": re.compile(r"(?<![\w.-])eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{0,2048}"),
        "private_key_block": re.compile(r"-----BEGIN (?:[A-Z]{1,20} ){0,4}PRIVATE KEY-----"),
        "credentials_in_url": re.compile(r"(?<![\w-])[a-z][a-z0-9+.-]{1,30}://[^\s:/@]{1,128}:[^\s:/@]{1,128}@"),
    }

    def find(self, text: str, document: str | None = None) -> Iterator[Finding]:
        """Scan one document."""
        for kind, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                yield self.finding(
                    beg=match.start(),
                    end=match.end(),
                    text=match.group(),
                    document=document,
                    context={"kind": kind},
                )
