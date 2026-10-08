import importlib
from collections.abc import Iterator
from dataclasses import dataclass, replace
from importlib.metadata import entry_points
from typing import TYPE_CHECKING

from scrubdaddy.exceptions import DuplicateDetectorError, MissingDependencyError, UnknownDetectorError
from scrubdaddy.locales import matches_locale

if TYPE_CHECKING:
    from scrubdaddy.detectors.base import Detector

__all__ = ["PLUGIN_GROUP", "Entry", "Registry", "plugin_entries"]

# Another package advertises a detector by adding it to this entry point
# group. Only the import path is read, so nothing from the plugin is
# imported until the detector is actually used.
PLUGIN_GROUP = "scrubdaddy.detectors"


@dataclass(frozen=True, slots=True)
class Entry:
    """What a registry knows about a detector before it is needed.

    The detector can be named as an import path instead of a class, so that a
    detector built on an optional dependency costs nothing until it is used.
    """

    name: str
    target: "str | type[Detector]"
    autoload: bool = True
    locales: frozenset[str] | None = None
    extra: str | None = None


def plugin_entries(autoload: bool = False) -> tuple[Entry, ...]:
    """What other installed packages advertise as detectors.

    Plugins stay out of the default set unless asked for: installing an
    unrelated package should not change what an existing scrubber does.
    """
    return tuple(
        Entry(name=point.name, target=point.value, autoload=autoload)
        for point in entry_points(group=PLUGIN_GROUP)
    )


class Registry:
    """A collection of detectors to choose from.

    An ordinary object rather than module-level state: a scrubber owns one, so
    registering a detector in one place cannot change what another scrubber in
    the same process sees.
    """

    def __init__(self, entries: "Iterator[Entry] | list[Entry] | None" = None) -> None:
        self._entries: dict[str, Entry] = {}
        self._loaded: dict[str, type[Detector]] = {}
        for entry in entries or ():
            self.add(entry)

    def __contains__(self, name: object) -> bool:
        return name in self._entries

    def __iter__(self) -> Iterator[Entry]:
        return iter(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"<Registry {len(self._entries)} detectors>"

    def copy(self) -> "Registry":
        """Branch off a private version that can be customised freely."""
        return Registry(list(self._entries.values()))

    def add(self, entry: Entry, replace_existing: bool = False) -> None:
        """Take a detector into the registry."""
        if entry.name in self._entries and not replace_existing:
            raise DuplicateDetectorError(entry.name)
        self._entries[entry.name] = entry
        self._loaded.pop(entry.name, None)

    def register(
        self,
        detector: "type[Detector]",
        autoload: bool = False,
        locales: frozenset[str] | None = None,
        extra: str | None = None,
        replace_existing: bool = False,
    ) -> "type[Detector]":
        """Take an already imported detector, usable as a decorator.

        Registering does not enrol the detector into the default set unless
        asked: adding a detector should not quietly change what every scrubber
        built afterwards does.
        """
        entry = Entry(
            name=detector.name,
            target=detector,
            autoload=autoload,
            locales=locales if locales is not None else detector.locales,
            extra=extra,
        )
        self.add(entry, replace_existing=replace_existing)
        return detector

    def add_plugins(self, autoload: bool = False) -> tuple[str, ...]:
        """Take in the detectors other installed packages advertise.

        A plugin claiming a name that is already in use is passed over rather
        than allowed to shadow it or to break building the registry; comparing
        the result with the advertised entries shows which ones lost.
        """
        added: list[str] = []
        for entry in plugin_entries(autoload=autoload):
            if entry.name in self._entries:
                continue
            self.add(entry)
            added.append(entry.name)
        return tuple(added)

    def remove(self, name: str, missing_ok: bool = True) -> None:
        """Drop a detector.

        Removing something that is not there is not worth interrupting a
        pipeline for, so it is tolerated by default.
        """
        if name not in self._entries:
            if missing_ok:
                return
            raise UnknownDetectorError(name, self.names())
        del self._entries[name]
        self._loaded.pop(name, None)

    def set_autoload(self, name: str, autoload: bool) -> None:
        """Move a detector into or out of the default set."""
        self._entries[name] = replace(self.entry(name), autoload=autoload)

    def names(self) -> tuple[str, ...]:
        """Registered names, in registration order."""
        return tuple(self._entries)

    def entry(self, name: str) -> Entry:
        """Look up what is known about one detector."""
        try:
            return self._entries[name]
        except KeyError:
            raise UnknownDetectorError(name, self.names()) from None

    def load(self, name: str) -> "type[Detector]":
        """Resolve a registration to a class, importing it if needed."""
        cached = self._loaded.get(name)
        if cached is not None:
            return cached

        entry = self.entry(name)
        if not isinstance(entry.target, str):
            self._loaded[name] = entry.target
            return entry.target

        module_path, _, class_name = entry.target.partition(":")
        try:
            module = importlib.import_module(module_path)
        except ImportError as exc:
            if entry.extra is not None:
                raise MissingDependencyError(name, entry.extra) from exc
            raise
        detector_cls: type[Detector] = getattr(module, class_name)
        self._loaded[name] = detector_cls
        return detector_cls

    def select(self, locale: str, names: "list[str] | tuple[str, ...] | None" = None) -> tuple[Entry, ...]:
        """Decide which detectors a scrubber should run.

        Naming detectors explicitly overrides the default set but not the
        locale: asking for a detector that cannot work in the chosen locale
        silently gets you nothing rather than nonsense findings.
        """
        wanted = [self.entry(name) for name in names] if names is not None else [e for e in self if e.autoload]
        return tuple(entry for entry in wanted if matches_locale(locale, entry.locales))
