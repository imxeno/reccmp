"""Delphi 7 line numbers past 32767 in units that use `{$I}` includes.

Up to line 32767 Delphi 7 records the line of the file a statement is in. Past
that, it records a physical line instead: the line within the unit with the
text of every include compiled so far counted in place, each include adding
its number of line breaks (nested includes count in their own place). Code
from an include whose physical line is past 32767 is recorded under the
including file at those physical lines too. The functions here map such
numbers back to lines of the source file, where markers are read."""

import logging
import re
from pathlib import PurePath
from typing import Callable, Iterator

from reccmp.parser.delphi import blank_inactive_conditionals

logger = logging.getLogger(__name__)

# Highest line Delphi 7 records as a plain line of the file.
LAST_LOGICAL_LINE = 0x7FFF

_include_token_regex = re.compile(
    r"//[^\r\n]*|'(?:''|[^'\r\n])*'|\(\*.*?\*\)"
    r"|\{\$(?:INCLUDE|I)\s+(?P<name>[^}]*?)\s*\}"
    r"|\{[^}]*\}",
    flags=re.I | re.S,
)

# Resolves an include name used by the given file to the included text.
IncludeLookup = Callable[[str, PurePath], tuple[PurePath, str] | None]


def iter_include_sites(
    text: str, defines: dict[str, bool]
) -> Iterator[tuple[int, str]]:
    """Yield (line, name) for each `{$I name}` / `{$INCLUDE name}` directive
    the build compiles, ignoring comments, strings and inactive branches."""

    text = blank_inactive_conditionals(text, defines)
    for match in _include_token_regex.finditer(text):
        name = match.group("name")
        if name is None:
            continue
        line = text.count("\n", 0, match.start()) + 1
        yield line, name.strip().strip("'")


class PhysicalLineMap:
    """Maps Delphi 7 physical line numbers of one source file to its lines."""

    def __init__(self, sites: list[tuple[int, int]]) -> None:
        # (line of the include directive, line breaks of the included text)
        self.sites = sorted(sites)

    def logical_line(self, physical: int) -> int:
        """The source line for a recorded line number. Numbers past 32767 are
        physical; a number inside an include's text maps to its directive."""

        if physical <= LAST_LOGICAL_LINE:
            return physical

        offset = 0
        for line, size in self.sites:
            start = line + offset
            if physical < start:
                break
            if physical <= start + size:
                return line
            offset += size
        return physical - offset


def _included_line_breaks(
    name: str,
    including: PurePath,
    lookup: IncludeLookup,
    defines: dict[str, bool],
    depth: int = 0,
) -> int | None:
    included = lookup(name, including)
    if included is None or depth > 16:
        return None

    path, text = included
    total = text.count("\n")
    for _, nested in iter_include_sites(text, defines):
        size = _included_line_breaks(nested, path, lookup, defines, depth + 1)
        if size is None:
            return None
        total += size
    return total


def physical_line_map(
    path: PurePath, text: str, lookup: IncludeLookup, defines: dict[str, bool]
) -> PhysicalLineMap | None:
    """The physical line map of a source file, or None if one of its includes
    cannot be found."""

    sites: list[tuple[int, int]] = []
    for line, name in iter_include_sites(text, defines):
        size = _included_line_breaks(name, path, lookup, defines)
        if size is None:
            logger.warning(
                "Cannot read include '%s' of %s: its line numbers past %d stay unmapped",
                name,
                path,
                LAST_LOGICAL_LINE,
            )
            return None
        sites.append((line, size))
    return PhysicalLineMap(sites)
