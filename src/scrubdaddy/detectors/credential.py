import re
from typing import ClassVar

from scrubdaddy.detectors.base import RegexDetector
from scrubdaddy.models import PiiType

__all__ = ["PasswordDetector"]


class PasswordDetector(RegexDetector):
    """Finds the value that follows a password-like label."""

    name = "password"
    pii_type = PiiType.CREDENTIAL
    group = "secret"

    _LABELS = r"passwords?|passwd|passphrase|pwd|pass|secret|api[_-]?key|apikey|token|auth|credentials?"

    pattern: ClassVar[re.Pattern[str]] = re.compile(
        rf"""
        (?<![\w-])
        (?:[a-z0-9]{{1,32}}[_-])?           # new_password, user-token
        (?:{_LABELS})
        (?:[_-][a-z0-9]{{1,32}})?           # password_confirmation
        (?![\w-])
        ["']?                               # the label is quoted in JSON
        [\t ]{{0,8}}
        [:=]>?                              # :, = or =>
        \s{{0,8}}
        (?P<quote>["'])?                    # the ? is outside the group on purpose:
        (?P<secret>                         # an absent quote must not take part in the
            (?(quote)                       # match, or the test below always sees one
                [^"']{{1,256}}               # quoted: spaces belong to the password
              | [^\s"'{{}},;&\]]{{1,256}}     # bare: stop where the format separates fields
            )
        )
        (?(quote)(?P=quote))
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
