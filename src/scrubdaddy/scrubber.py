import warnings
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from scrubdaddy.detectors import default_registry
from scrubdaddy.detectors.base import Detector
from scrubdaddy.exceptions import DetectorError
from scrubdaddy.limits import Limits
from scrubdaddy.locales import DEFAULT_LOCALE
from scrubdaddy.models import Finding
from scrubdaddy.registry import Registry
from scrubdaddy.render import Renderer, Token
from scrubdaddy.resolve import Strategy, resolve
from scrubdaddy.tokens import TokenMap

__all__ = ["DocumentsResult", "ScrubResult", "Scrubber"]

OnDetectorError = Literal["warn", "raise", "ignore"]


@dataclass(frozen=True, slots=True)
class ScrubResult:
    """The cleaned text together with what was found and how it was labelled."""

    text: str
    findings: tuple[Finding, ...]
    tokens: TokenMap


@dataclass(frozen=True, slots=True)
class DocumentsResult:
    """The cleaned documents together with what was found and how it was labelled."""

    documents: dict[str, str]
    findings: tuple[Finding, ...]
    tokens: TokenMap


class Scrubber:
    """Runs detectors over text and replaces what they find.

    All configuration lives on the instance, so two scrubbers in one process
    never influence each other: numbering, detector selection and locale are
    not shared through class attributes.
    """

    def __init__(  # noqa: PLR0913  # independent configuration options
        self,
        locale: str = DEFAULT_LOCALE,
        detectors: Sequence[str | Detector] | None = None,
        registry: Registry | None = None,
        min_score: float = 0.0,
        strategy: Strategy = Strategy.HIGHEST_SCORE,
        priority: Mapping[str, int] | None = None,
        renderer: Renderer | None = None,
        tokens: TokenMap | None = None,
        limits: Limits | None = None,
        on_detector_error: OnDetectorError = "warn",
    ) -> None:
        self.locale = locale
        self.registry = registry if registry is not None else default_registry()
        self.min_score = min_score
        self.strategy = strategy
        self.priority = dict(priority or {})
        self.renderer = renderer if renderer is not None else Token()
        self.tokens = tokens if tokens is not None else TokenMap()
        self.limits = limits if limits is not None else Limits()
        self.on_detector_error = on_detector_error
        self._detectors: dict[str, Detector] = {}

        names = [d for d in detectors or () if isinstance(d, str)] if detectors is not None else None
        for entry in self.registry.select(locale=locale, names=names):
            self.add_detector(self.registry.load(entry.name)(locale=locale))
        for detector in detectors or ():
            if not isinstance(detector, str):
                self.add_detector(detector)

    def __repr__(self) -> str:
        return f"<Scrubber locale={self.locale!r} detectors={len(self._detectors)}>"

    @property
    def detectors(self) -> tuple[Detector, ...]:
        """The detectors this scrubber will run, in order."""
        return tuple(self._detectors.values())

    def add_detector(self, detector: Detector) -> None:
        """Take a ready-made detector, replacing one of the same name."""
        self._detectors[detector.name] = detector

    def remove_detector(self, name: str) -> None:
        """Stop running a detector.

        Removing one that is not there is tolerated, so that configuration code
        does not have to know what the defaults happen to include.
        """
        self._detectors.pop(name, None)

    def find(self, text: str, document: str | None = None) -> list[Finding]:
        """Locate personal data without changing the text."""
        self.limits.check_document(len(text), document=document)
        return self._collect([text], [document])

    def find_documents(self, documents: Mapping[str, str] | Sequence[str]) -> list[Finding]:
        """Locate personal data across several documents."""
        names, texts = self._unpack(documents)
        return self._collect(texts, list(names))

    def scrub(self, text: str) -> ScrubResult:
        """Clean one text, keeping the findings and the labelling."""
        findings = self.find(text)
        return ScrubResult(
            text=self._replace(text, findings),
            findings=tuple(findings),
            tokens=self.tokens,
        )

    def scrub_documents(self, documents: Mapping[str, str] | Sequence[str]) -> DocumentsResult:
        """Clean several documents, keeping the findings and the labelling.

        The documents are processed together so that numbering and fingerprints
        are consistent across them.
        """
        names, texts = self._unpack(documents)
        findings = self._collect(texts, list(names))
        by_document: dict[str, list[Finding]] = {name: [] for name in names}
        for finding in findings:
            if finding.document is not None:
                by_document.setdefault(finding.document, []).append(finding)
        cleaned = {
            name: self._replace(text, by_document.get(name, ()), already_resolved=True)
            for name, text in zip(names, texts, strict=True)
        }
        return DocumentsResult(documents=cleaned, findings=tuple(findings), tokens=self.tokens)

    def clean(self, text: str) -> str:
        """Clean one text."""
        return self.scrub(text).text

    def clean_documents(self, documents: Mapping[str, str] | Sequence[str]) -> dict[str, str]:
        """Clean several documents."""
        return self.scrub_documents(documents).documents

    def _unpack(self, documents: Mapping[str, str] | Sequence[str]) -> tuple[list[str], list[str]]:
        if isinstance(documents, Mapping):
            names = list(documents.keys())
            texts = list(documents.values())
        else:
            texts = list(documents)
            names = [str(index) for index in range(len(texts))]
        total = 0
        for name, text in zip(names, texts, strict=True):
            self.limits.check_document(len(text), document=name)
            total += len(text)
        self.limits.check_total(total)
        return names, texts

    def _collect(self, texts: Sequence[str], documents: Sequence[str | None]) -> list[Finding]:
        """Run every detector and settle the overlaps, document by document."""
        found: dict[str | None, list[Finding]] = {name: [] for name in documents}
        count = 0
        for detector in self._detectors.values():
            for finding in self._run(detector, texts, documents):
                if finding.score < self.min_score:
                    continue
                found.setdefault(finding.document, []).append(finding)
                count += 1
        self.limits.check_findings(count)

        resolved: list[Finding] = []
        for document_findings in found.values():
            resolved.extend(resolve(document_findings, strategy=self.strategy, priority=self.priority))
        return resolved

    def _run(self, detector: Detector, texts: Sequence[str], documents: Sequence[str | None]) -> list[Finding]:
        """Shield the run from a single misbehaving detector."""
        try:
            return list(detector.find_batch(texts, documents))
        except Exception as exc:
            if self.on_detector_error == "raise":
                raise DetectorError(detector.name, exc) from exc
            if self.on_detector_error == "warn":
                # The message carries no document text, only the failure kind.
                warnings.warn(
                    f"detector {detector.name!r} failed and was skipped: {type(exc).__name__}",
                    RuntimeWarning,
                    stacklevel=3,
                )
            return []

    def _replace(self, text: str, findings: Iterable[Finding], already_resolved: bool = False) -> str:
        """Rebuild the text with replacements, in one pass."""
        ordered = list(findings)
        if not ordered:
            return text
        if not already_resolved:
            ordered = resolve(ordered, strategy=self.strategy, priority=self.priority)

        chunks: list[str] = []
        cursor = 0
        for finding in ordered:
            if finding.beg < cursor:
                # Overlapping spans would corrupt the output; keep-all is for
                # auditing, not for replacing.
                continue
            chunks.append(text[cursor : finding.beg])
            chunks.append(self.renderer.render(finding, self.tokens))
            cursor = finding.end
        chunks.append(text[cursor:])
        return "".join(chunks)
