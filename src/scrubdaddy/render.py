import abc

from scrubdaddy.models import Finding
from scrubdaddy.tokens import TokenMap

__all__ = ["Mask", "Remove", "Renderer", "Token"]


class Renderer(abc.ABC):
    """Decides what replaces a finding."""

    @abc.abstractmethod
    def render(self, finding: Finding, tokens: TokenMap) -> str:
        """Produce the replacement for one finding."""


class Token(Renderer):
    """Replaces personal data with a label such as ``{{EMAIL}}``.

    Numbering makes a document readable again, because the reader can tell that
    two mentions are the same person. A fingerprint does the same across
    documents without keeping a map, and requires a salt to be given: the space
    of phone or card numbers is small enough to walk through, so an unsalted
    fingerprint would be reversible by whoever holds the output.
    """

    def __init__(  # noqa: PLR0913  # independent presentation options
        self,
        prefix: str = "{{",
        suffix: str = "}}",
        include_kind: bool = True,
        include_count: bool = False,
        include_hash: bool = False,
        salt: str | bytes | None = None,
        hash_length: int = 8,
        uppercase: bool = True,
        separator: str = "-",
    ) -> None:
        if not (include_kind or include_count or include_hash):
            msg = "a token must include at least one of kind, count or hash"
            raise ValueError(msg)
        if include_hash and salt is None:
            msg = "include_hash requires an explicit salt, otherwise tokens are reversible by anyone"
            raise ValueError(msg)
        if hash_length < 1:
            msg = f"hash_length must be positive, got {hash_length}"
            raise ValueError(msg)
        self.prefix = prefix
        self.suffix = suffix
        self.include_kind = include_kind
        self.include_count = include_count
        self.include_hash = include_hash
        self.salt = salt.encode("utf-8") if isinstance(salt, str) else salt
        self.hash_length = hash_length
        self.uppercase = uppercase
        self.separator = separator

    def render(self, finding: Finding, tokens: TokenMap) -> str:
        """Produce the replacement for one finding."""
        pieces: list[str] = []
        if self.include_kind:
            pieces.append(finding.pii_type.replace(" ", "_"))
        if self.include_count:
            pieces.append(str(tokens.index_of(finding)))
        if self.include_hash and self.salt is not None:
            pieces.append(TokenMap.digest(finding.text.casefold(), salt=self.salt, length=self.hash_length))
        body = self.separator.join(pieces)
        if self.uppercase:
            body = body.upper()
        token = f"{self.prefix}{body}{self.suffix}"
        tokens.remember(token, finding)
        return token


class Mask(Renderer):
    """Replaces personal data with repeated characters.

    Keeping the last few characters is common for card numbers and phone
    numbers, where the tail is what lets a human recognise their own record
    without revealing the rest.
    """

    def __init__(self, char: str = "*", keep_last: int = 0, fixed_length: int | None = None) -> None:
        if len(char) != 1:
            msg = f"char must be a single character, got {len(char)} characters"
            raise ValueError(msg)
        if keep_last < 0:
            msg = f"keep_last must not be negative, got {keep_last}"
            raise ValueError(msg)
        if fixed_length is not None and fixed_length < 1:
            msg = f"fixed_length must be positive, got {fixed_length}"
            raise ValueError(msg)
        self.char = char
        self.keep_last = keep_last
        self.fixed_length = fixed_length

    def render(self, finding: Finding, tokens: TokenMap) -> str:
        """Produce the replacement for one finding."""
        del tokens
        tail = finding.text[-self.keep_last :] if self.keep_last else ""
        width = self.fixed_length if self.fixed_length is not None else max(len(finding) - len(tail), 0)
        return self.char * width + tail


class Remove(Renderer):
    """Deletes personal data outright, for when no placeholder is wanted."""

    def render(self, finding: Finding, tokens: TokenMap) -> str:
        """Produce the replacement for one finding."""
        del finding, tokens
        return ""
