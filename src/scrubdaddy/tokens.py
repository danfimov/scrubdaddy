import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any

from scrubdaddy.models import Finding

__all__ = ["GroupKey", "TokenMap", "default_group_key"]

GroupKey = Callable[[Finding], str]


def default_group_key(finding: Finding) -> str:
    """Treat two findings as the same entity when kind and text agree.

    Case is ignored, since the same address written in two cases is one
    address. Anything smarter than that is language-specific and belongs in a
    key function of its own.
    """
    return f"{finding.pii_type}:{finding.text.casefold()}"


class TokenMap:
    """Remembers which entity got which token.

    Lives on the scrubber rather than on the class, so two runs in one process
    cannot bleed numbering into each other, and can be carried over between
    runs so that the same person keeps the same token in tomorrow's batch.

    Keeping the original text is optional and off by default: a map that can
    undo the scrubbing is as sensitive as the document it came from.
    """

    def __init__(
        self,
        group_key: GroupKey = default_group_key,
        keep_originals: bool = False,
        counts: Mapping[str, int] | None = None,
        originals: Mapping[str, str] | None = None,
    ) -> None:
        self.group_key = group_key
        self.keep_originals = keep_originals
        self._counts: dict[str, int] = dict(counts or {})
        self._originals: dict[str, str] = dict(originals or {})
        self._next: dict[str, int] = {}
        for key, index in self._counts.items():
            kind = key.split(":", 1)[0]
            self._next[kind] = max(self._next.get(kind, 0), index + 1)

    def __len__(self) -> int:
        return len(self._counts)

    def __repr__(self) -> str:
        return f"<TokenMap {len(self._counts)} entities keep_originals={self.keep_originals}>"

    def index_of(self, finding: Finding) -> int:
        """Stable per-entity number, counted separately for each kind."""
        key = self.group_key(finding)
        known = self._counts.get(key)
        if known is not None:
            return known
        index = self._next.get(finding.pii_type, 0)
        self._next[finding.pii_type] = index + 1
        self._counts[key] = index
        return index

    def remember(self, token: str, finding: Finding) -> None:
        """Record what a token stands for, when reversal is wanted."""
        if self.keep_originals:
            self._originals[token] = finding.text

    def original_of(self, token: str) -> str | None:
        """Look up what a token stood for."""
        return self._originals.get(token)

    def to_dict(self, include_originals: bool = False) -> dict[str, Any]:
        """Render for storage between runs.

        Originals are withheld unless explicitly asked for, so that writing the
        map to a log or a build artefact does not undo the scrubbing.
        """
        payload: dict[str, Any] = {"counts": dict(self._counts)}
        if include_originals and self._originals:
            payload["originals"] = dict(self._originals)
        return payload

    def to_json(self, include_originals: bool = False) -> str:
        """Render for storage between runs."""
        return json.dumps(self.to_dict(include_originals=include_originals), sort_keys=True)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any], group_key: GroupKey = default_group_key) -> "TokenMap":
        """Pick up numbering where an earlier run left off."""
        originals = payload.get("originals") or {}
        return cls(
            group_key=group_key,
            keep_originals=bool(originals),
            counts=payload.get("counts") or {},
            originals=originals,
        )

    @staticmethod
    def digest(text: str, salt: bytes, length: int) -> str:
        """Short, salted fingerprint of an entity.

        Salted because the space of phone numbers or card numbers is small
        enough to walk through, which would make an unsalted fingerprint
        reversible by anyone holding the output.
        """
        return hashlib.blake2b(text.encode("utf-8"), key=salt, digest_size=32).hexdigest()[:length].upper()
