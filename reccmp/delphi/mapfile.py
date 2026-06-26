"""Reader for detailed Delphi/C++Builder MAP files."""

import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import NamedTuple

from reccmp.cvdump.analysis import CvdumpNode
from reccmp.cvdump.parser import LineValue, NodeKey
from reccmp.cvdump.types import CvdumpTypesParser
from reccmp.types import EntityType

_section_regex = re.compile(
    r"^\s*(?P<section>[0-9A-F]{4}):(?P<start>[0-9A-F]{8})\s+"
    r"(?P<length>[0-9A-F]+)H?\s+(?P<name>\S+)\s+(?P<class>\S+)",
    flags=re.I,
)

_public_regex = re.compile(
    r"^\s*(?P<section>[0-9A-F]{4}):(?P<offset>[0-9A-F]{4,8})\s+" + r"(?P<name>\S.*)$",
    flags=re.I,
)

_line_header_regex = re.compile(
    r"^\s*Line numbers for .*\((?P<filename>.+)\) segment .*$",
    flags=re.I,
)

_line_pair_regex = re.compile(
    r"\s*(?P<line_no>\d+)\s+" + r"(?P<section>[0-9A-F]{4}):(?P<offset>[0-9A-F]{4,8})",
    flags=re.I,
)

_publics_header_regex = re.compile(r"^Address\s+Publics by (?:Name|Value)$", flags=re.I)

_segment_contribution_regex = re.compile(
    r"^\s*(?P<section>[0-9A-F]{4}):(?P<start>[0-9A-F]{4,8})\s+"
    r"(?P<length>[0-9A-F]+)H?\s+"
    r"(?=.*\bC=CODE\b)(?=.*\bM=(?P<module>\S+)).*$",
    flags=re.I,
)


class MapPublic(NamedTuple):
    section: int
    offset: int
    name: str


class MapSegmentContribution(NamedTuple):
    section: int
    start: int
    end: int
    module: str


@dataclass
class DelphiMapParser:
    """Parse the symbol and line sections from a detailed MAP file."""

    section_classes: dict[int, str]
    publics: list[MapPublic]
    lines: dict[PureWindowsPath, list[LineValue]]
    code_contributions: list[MapSegmentContribution]

    def __init__(self) -> None:
        self.section_classes = {}
        self.publics = []
        self.lines = {}
        self.code_contributions = []
        self._mode: str | None = None
        self._current_line_file = PureWindowsPath()
        self._seen_publics: set[tuple[int, int, str]] = set()

    def _read_section_line(self, line: str):
        if (match := _section_regex.match(line)) is not None:
            self.section_classes[int(match.group("section"), 16)] = match.group(
                "class"
            ).upper()

    def _read_segment_contribution_line(self, line: str):
        if (match := _segment_contribution_regex.match(line)) is None:
            return

        start = int(match.group("start"), 16)
        length = int(match.group("length"), 16)
        self.code_contributions.append(
            MapSegmentContribution(
                section=int(match.group("section"), 16),
                start=start,
                end=start + length,
                module=match.group("module"),
            )
        )

    def _read_public_line(self, line: str):
        if (match := _public_regex.match(line)) is None:
            return

        public = MapPublic(
            section=int(match.group("section"), 16),
            offset=int(match.group("offset"), 16),
            name=match.group("name").strip(),
        )
        public_key = (public.section, public.offset, public.name)
        if public_key not in self._seen_publics:
            self.publics.append(public)
            self._seen_publics.add(public_key)

    def _read_line_number_line(self, line: str):
        if (match := _line_header_regex.match(line)) is not None:
            self._current_line_file = PureWindowsPath(match.group("filename"))
            self.lines.setdefault(self._current_line_file, [])
            return

        for match in _line_pair_regex.finditer(line):
            self.lines.setdefault(self._current_line_file, []).append(
                LineValue(
                    line_number=int(match.group("line_no")),
                    section=int(match.group("section"), 16),
                    offset=int(match.group("offset"), 16),
                )
            )

    def read_line(self, line: str):
        stripped = line.strip()
        self._read_segment_contribution_line(line)

        if stripped == "Start         Length      Name                   Class" or (
            stripped.startswith("Start")
            and "Length" in stripped
            and "Class" in stripped
        ):
            self._mode = "sections"
            return

        if stripped == "Detailed map of segments":
            self._mode = None
            return

        if _publics_header_regex.match(stripped):
            self._mode = "publics"
            return

        if stripped.startswith("Line numbers for "):
            self._mode = "lines"
            self._read_line_number_line(line)
            return

        if not stripped:
            return

        if self._mode == "sections":
            self._read_section_line(line)
        elif self._mode == "publics":
            self._read_public_line(line)
        elif self._mode == "lines":
            self._read_line_number_line(line)

    def read(self, text: str):
        for line in text.splitlines():
            self.read_line(line)

    def owner_unit_at(self, section: int, offset: int) -> str | None:
        owners = {
            contribution.module
            for contribution in self.code_contributions
            if contribution.section == section
            and contribution.start <= offset < contribution.end
        }

        if len(owners) == 1:
            return next(iter(owners))

        return None


class DelphiMapAnalysis:
    """CvdumpAnalysis-compatible view of a detailed MAP file."""

    parser: DelphiMapParser
    lines: dict[PureWindowsPath, list[LineValue]]
    nodes: list[CvdumpNode]
    types: CvdumpTypesParser

    def __init__(self, parser: DelphiMapParser):
        self.parser = parser
        node_dict: dict[NodeKey, CvdumpNode] = {}

        for public in parser.publics:
            key = NodeKey(public.section, public.offset)
            if key in node_dict:
                continue

            node_dict[key] = CvdumpNode(
                section=public.section,
                offset=public.offset,
                decorated_name=public.name,
                friendly_name=public.name,
                node_type=self._node_type(public),
                owner_unit=parser.owner_unit_at(public.section, public.offset),
            )

        self.lines = parser.lines
        self.nodes = [v for _, v in dict(sorted(node_dict.items())).items()]
        self.types = CvdumpTypesParser()
        self._estimate_size()

    @classmethod
    def from_text(cls, text: str) -> "DelphiMapAnalysis":
        parser = DelphiMapParser()
        parser.read(text)
        return cls(parser)

    @classmethod
    def from_file(cls, path: Path, *, encoding: str = "utf-8") -> "DelphiMapAnalysis":
        return cls.from_text(path.read_text(encoding=encoding))

    def _node_type(self, public: MapPublic) -> EntityType | None:
        section_class = self.parser.section_classes.get(public.section)
        if section_class == "CODE":
            return EntityType.FUNCTION

        if section_class in ("DATA", "BSS", "TLS", "CONST"):
            return EntityType.DATA

        return None

    def _estimate_size(self):
        for i in range(len(self.nodes) - 1):
            this_node = self.nodes[i]
            next_node = self.nodes[i + 1]

            if this_node.section != next_node.section:
                continue

            this_node.estimated_size = next_node.offset - this_node.offset
