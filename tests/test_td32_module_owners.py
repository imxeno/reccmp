"""TD32 module identity is independent of source and executable filenames."""

import struct
from pathlib import PurePath, PureWindowsPath
from typing import cast
from unittest.mock import Mock

import pytest

from reccmp.compare.asm.replacement import create_name_lookup
from reccmp.compare.db import EntityDb
from reccmp.compare.ingest import load_cvdump, load_markers
from reccmp.compare.lines import LinesDb
from reccmp.compare.match_msvc import match_variables
from reccmp.cvdump.cvinfo import CVInfoTypeEnum
from reccmp.delphi import DelphiTd32Analysis, DelphiTd32Parser
from reccmp.delphi.td32 import Td32SourceRange
from reccmp.formats import PEImage, TextFile
from reccmp.types import EntityType, ImageId

from .test_delphi_td32 import (
    _names_subsection,
    _source_subsection,
    _symbol_record,
    _td32_stream,
)


def module_record(name_index=4):
    # TModuleInfo: 28-byte header plus one 12-byte segment descriptor.
    return struct.pack(
        "<HHHHIIIIIHHII", 0, 0, 1, 0x4356, name_index, 0, 0, 0, 0, 1, 1, 0x10, 0x30
    )


def module_stream(*, filename="SharedEntry.dpr", records=None, with_source=True):
    names = _names_subsection(
        [filename, "Initialization", "Buffer", "Launcher", "Other"]
    )
    procedure = struct.pack(
        "<IIIIIIIHHIII", 0, 0, 0, 0x30, 0, 0x30, 0x10, 1, 0, 0, 2, 0
    )
    data = struct.pack("<IHHIII", 0x20, 2, 0, CVInfoTypeEnum.T_32PVOID, 3, 0)
    symbols = (
        struct.pack("<I", 0)
        + _symbol_record(0x0205, procedure)
        + _symbol_record(0x0006, b"")
        + _symbol_record(0x0202, data)
    )
    # Deliberately put names/modules after symbols and source records.
    sections = [(0x0125, 1, symbols)]
    if with_source:
        sections.append((0x0127, 1, _source_subsection({"Unit1.pas": 1})))
    sections += [
        (0x0120, 1, value)
        for value in ([module_record()] if records is None else records)
    ]
    sections.append((0x0130, 0, names))
    return _td32_stream(sections)


@pytest.mark.parametrize(
    "filename", ["Client.dpr", "ClientX.dpr", "UnitAlias.pas", "Package.dpk"]
)
def test_declared_module_name_owns_symbols_and_source_ranges(filename):
    analysis = DelphiTd32Analysis.from_bytes(module_stream(filename=filename))
    parser = cast(DelphiTd32Parser, analysis.parser)
    assert parser.module_owner_units == {1: "Launcher"}
    assert parser.data_owner_units == {(2, 0x20): "Launcher"}
    assert parser.source_ranges == [
        Td32SourceRange(section=1, start=0x10, end=0x40, owner_unit="Launcher")
    ]
    assert PureWindowsPath(filename) in analysis.lines
    function = next(
        node for node in analysis.nodes if node.node_type == EntityType.FUNCTION
    )
    variable = next(
        node for node in analysis.nodes if node.node_type == EntityType.DATA
    )
    assert function.name() == "Launcher.Initialization"
    assert variable.name() == "Buffer"
    assert function.owner_unit == variable.owner_unit == "Launcher"


def test_module_name_owns_data_without_source_lines():
    parser = DelphiTd32Parser.from_bytes(module_stream(with_source=False))
    assert parser.module_owner_units == {1: "Launcher"}
    assert parser.data_owner_units == {(2, 0x20): "Launcher"}
    assert not parser.lines


def test_distinct_modules_can_share_a_source_filename_and_variable_name():
    sections = [
        (
            0x0130,
            0,
            _names_subsection(["Shared.inc", "", "Buffer", "Launcher", "Other"]),
        )
    ]
    for module_index, name_index, offset in ((1, 4, 0x20), (2, 5, 0x24)):
        sections.extend(
            [
                (0x0120, module_index, module_record(name_index)),
                (0x0127, module_index, _source_subsection({"Unit1.pas": 1})),
                (
                    0x0125,
                    module_index,
                    struct.pack("<I", 0)
                    + _symbol_record(
                        0x0202,
                        struct.pack(
                            "<IHHIII", offset, 2, 0, CVInfoTypeEnum.T_32PVOID, 3, 0
                        ),
                    ),
                ),
            ]
        )

    parser = DelphiTd32Parser.from_bytes(_td32_stream(sections))

    assert parser.module_owner_units == {1: "Launcher", 2: "Other"}
    assert parser.data_owner_units == {(2, 0x20): "Launcher", (2, 0x24): "Other"}


@pytest.mark.parametrize(
    "records",
    [
        [],
        [b""],
        [module_record()[:8]],
        [module_record()[:27]],
        [module_record()[:-1]],
        [module_record(0)],
        [module_record(999)],
    ],
)
def test_missing_or_invalid_module_record_preserves_source_fallback(records):
    parser = DelphiTd32Parser.from_bytes(module_stream(records=records))
    assert parser.module_owner_units == {1: "SharedEntry"}
    assert parser.data_owner_units == {(2, 0x20): "SharedEntry"}


def test_duplicate_module_records_agree():
    parser = DelphiTd32Parser.from_bytes(module_stream(records=[module_record()] * 2))
    assert parser.module_owner_units == {1: "Launcher"}
    assert parser.data_owner_units == {(2, 0x20): "Launcher"}


def test_conflicting_declared_modules_do_not_fall_back_to_a_filename(caplog):
    parser = DelphiTd32Parser.from_bytes(
        module_stream(records=[module_record(4), module_record(5)])
    )
    assert not parser.module_owner_units
    assert not parser.data_owner_units
    assert not parser.source_ranges
    assert "Conflicting TD32 module owners" in caplog.text
    assert PureWindowsPath("SharedEntry.dpr") in parser.lines


def test_shared_program_matches_globals_independently_for_each_target():
    source = TextFile(
        PurePath("SharedEntry.dpr"),
        """program Launcher;
var
  // GLOBAL: CLIENT 0x401000
  // GLOBAL: CLIENTX 0x501000
  Buffer: Pointer;
begin
{$IFDEF CLIENT_X}
  Buffer := nil;
{$ELSE}
  Buffer := nil;
{$ENDIF}
end.
""",
    )
    for target, original, other_original, rebuilt_base in (
        ("CLIENT", 0x401000, 0x501000, 0x600000),
        ("CLIENTX", 0x501000, 0x401000, 0x700000),
    ):
        analysis = DelphiTd32Analysis.from_bytes(module_stream())
        image = Mock(spec=PEImage)
        image.is_valid_section.return_value = True
        image.is_valid_vaddr.return_value = True
        image.get_section_extent_by_index.return_value = 0x1000
        image.get_abs_addr.side_effect = lambda section, offset, base=rebuilt_base: (
            base + section * 0x1000 + offset
        )
        db = EntityDb()
        load_cvdump(analysis, db, image)
        load_markers([source], LinesDb(), image, target, db)
        with db.batch() as batch:
            batch.set(
                ImageId.RECOMP,
                0x900000,
                type=EntityType.DATA,
                name="Buffer",
                owner_unit="Other",
                is_delphi=True,
            )
        match_variables(db)

        rebuilt = rebuilt_base + 0x2020
        assert db.is_match(original, rebuilt)
        assert db.get(ImageId.ORIG, other_original, exact=True) is None
        other_global = db.get(ImageId.RECOMP, 0x900000)
        assert other_global is not None
        assert other_global.orig_addr is None
        orig_name = create_name_lookup(db, ImageId.ORIG, lambda _: None)(original)
        recomp_name = create_name_lookup(db, ImageId.RECOMP, lambda _: None)(rebuilt)
        assert orig_name == recomp_name == "Launcher.Buffer (DATA)"
