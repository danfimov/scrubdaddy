__all__ = [
    "DetectorError",
    "DuplicateDetectorError",
    "LimitExceededError",
    "MissingDependencyError",
    "ScrubdaddyError",
    "UnknownDetectorError",
]


class ScrubdaddyError(Exception):
    """Base class for every error raised by scrubdaddy.

    Messages never include detected text, so that tracebacks and error
    reporting systems do not become another place where personal data leaks.
    """


class UnknownDetectorError(ScrubdaddyError, KeyError):
    """A detector was requested by a name nothing is registered under."""

    def __init__(self, name: str, known: tuple[str, ...] = ()) -> None:
        self.name = name
        self.known = known
        suffix = f"; known detectors: {', '.join(known)}" if known else ""
        super().__init__(f"unknown detector {name!r}{suffix}")


class DuplicateDetectorError(ScrubdaddyError, KeyError):
    """Two detectors claim the same name."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"detector {name!r} is already registered; remove it first or pass replace_existing=True")


class MissingDependencyError(ScrubdaddyError, ImportError):
    """A detector needs an optional dependency that is not installed.

    The message names the extra to install, since the bare import error gives
    no hint about which feature it belongs to.
    """

    def __init__(self, detector: str, extra: str) -> None:
        self.detector = detector
        self.extra = extra
        super().__init__(f"detector {detector!r} needs an optional dependency: pip install 'scrubdaddy[{extra}]'")


class DetectorError(ScrubdaddyError):
    """A detector failed while scanning and the scrubber was asked to raise."""

    def __init__(self, detector: str, cause: BaseException) -> None:
        self.detector = detector
        self.cause = cause
        super().__init__(f"detector {detector!r} failed: {type(cause).__name__}")


class LimitExceededError(ScrubdaddyError, ValueError):
    """The input, or the amount of work it triggered, went past a limit."""

    def __init__(self, what: str, actual: int, limit: int) -> None:
        self.what = what
        self.actual = actual
        self.limit = limit
        super().__init__(f"{what} is {actual}, which exceeds the limit of {limit}")
