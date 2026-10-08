import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from scrubdaddy import __version__
from scrubdaddy.detectors import default_registry
from scrubdaddy.exceptions import ScrubdaddyError
from scrubdaddy.models import Finding
from scrubdaddy.registry import plugin_entries
from scrubdaddy.render import Mask, Remove, Renderer, Token
from scrubdaddy.resolve import Strategy
from scrubdaddy.scrubber import Scrubber

__all__ = ["main"]

STDIN_NAME = "-"
USAGE_ERROR = 2
FOUND_SOMETHING = 1


def _add_shared(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--locale", default="en_US", help="locale of the input, e.g. ru_RU (default: en_US)")
    parser.add_argument(
        "--detectors",
        metavar="NAMES",
        help="comma-separated detectors to use instead of the default set",
    )
    parser.add_argument("--min-score", type=float, default=0.0, metavar="N", help="ignore findings below this score")
    parser.add_argument(
        "--strategy",
        choices=[str(s) for s in Strategy],
        default=str(Strategy.HIGHEST_SCORE),
        help="how to settle detectors claiming overlapping text",
    )


def build_parser() -> argparse.ArgumentParser:
    """Describe the command line."""
    parser = argparse.ArgumentParser(
        prog="scrubdaddy",
        description="Find and remove personal data in text.",
    )
    parser.add_argument("--version", action="version", version=f"scrubdaddy {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    clean = commands.add_parser("clean", help="write the text back with personal data replaced")
    clean.add_argument("file", nargs="?", default=STDIN_NAME, help="file to read, or - for standard input")
    _add_shared(clean)
    clean.add_argument("--renderer", choices=["token", "mask", "remove"], default="token")
    clean.add_argument("--count", action="store_true", help="number each entity, as in {{EMAIL-0}}")
    clean.add_argument(
        "--hash-salt",
        metavar="SALT",
        help="label each entity with a salted fingerprint instead of a number",
    )
    clean.add_argument("--mask-char", default="*", metavar="CHAR")
    clean.add_argument("--keep-last", type=int, default=0, metavar="N", help="characters to leave visible when masking")

    find = commands.add_parser("find", help="report personal data without changing the text")
    find.add_argument("files", nargs="*", default=[STDIN_NAME], help="files to read, or - for standard input")
    _add_shared(find)
    find.add_argument("--json", action="store_true", dest="as_json", help="one JSON object per finding")
    find.add_argument("--include-text", action="store_true", help="include the matched text in the output")
    find.add_argument(
        "--exit-code",
        action="store_true",
        help=f"exit with {FOUND_SOMETHING} when anything was found, for use in a pipeline",
    )

    listing = commands.add_parser("list-detectors", help="show the detectors available here")
    listing.add_argument("--locale", default="en_US")
    listing.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _renderer(args: argparse.Namespace) -> Renderer:
    if args.renderer == "mask":
        return Mask(char=args.mask_char, keep_last=args.keep_last)
    if args.renderer == "remove":
        return Remove()
    salt: str | None = args.hash_salt
    return Token(include_count=args.count, include_hash=salt is not None, salt=salt)


def _scrubber(args: argparse.Namespace, renderer: Renderer | None = None) -> Scrubber:
    names: list[str] | None = None
    if args.detectors:
        names = [name.strip() for name in str(args.detectors).split(",") if name.strip()]
    return Scrubber(
        locale=args.locale,
        detectors=names,
        min_score=args.min_score,
        strategy=Strategy(args.strategy),
        renderer=renderer,
    )


def _read(name: str, stdin: TextIO) -> str:
    if name == STDIN_NAME:
        return stdin.read()
    return Path(name).read_text(encoding="utf-8")


def _clean(args: argparse.Namespace, stdout: TextIO, stdin: TextIO) -> int:
    text = _read(args.file, stdin)
    stdout.write(_scrubber(args, _renderer(args)).clean(text))
    return 0


def _report(finding: Finding, include_text: bool) -> str:
    where = f"{finding.document}:{finding.beg}-{finding.end}"
    row = f"{where}\t{finding.pii_type}\t{finding.score:.2f}\t{finding.detector}"
    return f"{row}\t{finding.text}" if include_text else row


def _find(args: argparse.Namespace, stdout: TextIO, stdin: TextIO) -> int:
    documents = {name: _read(name, stdin) for name in args.files}
    findings = _scrubber(args).find_documents(documents)
    for finding in findings:
        if args.as_json:
            stdout.write(json.dumps(finding.to_dict(include_text=args.include_text)) + "\n")
        else:
            stdout.write(_report(finding, args.include_text) + "\n")
    if args.exit_code and findings:
        return FOUND_SOMETHING
    return 0


@dataclass(frozen=True, slots=True)
class _Row:
    """One line of the detector listing."""

    name: str
    default: bool
    locales: tuple[str, ...]
    extra: str | None
    plugin: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "default": self.default,
            "locales": list(self.locales) or None,
            "extra": self.extra,
            "plugin": self.plugin,
        }

    def to_line(self) -> str:
        marks = [
            "default" if self.default else "opt-in",
            f"extra={self.extra}" if self.extra else "",
            "plugin" if self.plugin else "",
            ",".join(self.locales),
        ]
        return "{}\t{}".format(self.name, "\t".join(mark for mark in marks if mark))


def _list_detectors(args: argparse.Namespace, stdout: TextIO) -> int:
    # Built in first, then the plugins, so that the ones that lost their name
    # to something already registered can be named rather than silently gone.
    registry = default_registry(plugins=False)
    advertised = {entry.name for entry in plugin_entries()}
    from_plugins = set(registry.add_plugins())
    selected = {entry.name for entry in registry.select(locale=args.locale)}
    rows = [
        _Row(
            name=entry.name,
            default=entry.name in selected,
            locales=tuple(sorted(entry.locales)) if entry.locales else (),
            extra=entry.extra,
            plugin=entry.name in from_plugins,
        )
        for entry in registry
    ]
    if args.as_json:
        stdout.write(json.dumps([row.to_dict() for row in rows], indent=2) + "\n")
        return 0
    stdout.writelines(row.to_line() + "\n" for row in rows)
    shadowed = sorted(advertised - from_plugins)
    if shadowed:
        stdout.write(f"\nnot used, the name is taken: {', '.join(shadowed)}\n")
    return 0


def main(
    argv: Sequence[str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    stdin: TextIO | None = None,
) -> int:
    """Run one command, returning the exit code."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    source = stdin if stdin is not None else sys.stdin

    args = build_parser().parse_args(argv)
    try:
        if args.command == "clean":
            return _clean(args, out, source)
        if args.command == "find":
            return _find(args, out, source)
        return _list_detectors(args, out)
    except ScrubdaddyError as exc:
        err.write(f"scrubdaddy: {exc}\n")
        return USAGE_ERROR
    except OSError as exc:
        err.write(f"scrubdaddy: {exc.strerror}: {exc.filename}\n")
        return USAGE_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
