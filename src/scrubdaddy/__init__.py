from scrubdaddy.detectors import Detector, RegexDetector, default_registry
from scrubdaddy.exceptions import (
    DetectorError,
    DuplicateDetectorError,
    LimitExceededError,
    MissingDependencyError,
    ScrubdaddyError,
    UnknownDetectorError,
)
from scrubdaddy.limits import Limits
from scrubdaddy.locales import DEFAULT_LOCALE
from scrubdaddy.models import Finding, PiiType
from scrubdaddy.registry import Entry, Registry
from scrubdaddy.render import Mask, Remove, Renderer, Token
from scrubdaddy.resolve import Strategy
from scrubdaddy.scrubber import DocumentsResult, Scrubber, ScrubResult
from scrubdaddy.tokens import TokenMap

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_LOCALE",
    "Detector",
    "DetectorError",
    "DocumentsResult",
    "DuplicateDetectorError",
    "Entry",
    "Finding",
    "LimitExceededError",
    "Limits",
    "Mask",
    "MissingDependencyError",
    "PiiType",
    "RegexDetector",
    "Registry",
    "Remove",
    "Renderer",
    "ScrubResult",
    "Scrubber",
    "ScrubdaddyError",
    "Strategy",
    "Token",
    "TokenMap",
    "UnknownDetectorError",
    "__version__",
    "clean",
    "default_registry",
    "find",
]


def clean(text: str, locale: str = DEFAULT_LOCALE, **kwargs: object) -> str:
    """Clean one text with a throwaway scrubber.

    Convenient for a one-off; building a scrubber once is cheaper when there is
    more than one text, and is the only way to carry numbering between calls.
    """
    return Scrubber(locale=locale, **kwargs).clean(text)  # type: ignore[arg-type]


def find(text: str, locale: str = DEFAULT_LOCALE, **kwargs: object) -> list[Finding]:
    """Locate personal data in one text with a throwaway scrubber."""
    return Scrubber(locale=locale, **kwargs).find(text)  # type: ignore[arg-type]
