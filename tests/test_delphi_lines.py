"""Delphi 7 physical line numbers past line 32767 in units with includes.

The expected numbers are those Delphi 7 (7.0.4.453) recorded in the TD32 line
table of test programs compiled for this purpose."""

from pathlib import PurePath, PureWindowsPath
from textwrap import dedent

from reccmp.compare.ingest import remap_delphi_physical_lines
from reccmp.compare.lines import LinesDb
from reccmp.delphi.lines import (
    PhysicalLineMap,
    iter_include_sites,
    physical_line_map,
)
from reccmp.formats import TextFile


def _filler_unit(sites: dict[int, str], length: int) -> str:
    lines = ["// filler"] * length
    for line, name in sites.items():
        lines[line - 1] = f"  {{$I {name}}}"
    return "\r\n".join(lines) + "\r\n"


A_INC = "// a1\r\n// a2\r\n// a3\r\nG := G + 1;\r\n// a5\r\n"  # 5 line breaks
B_INC = "// b\r\n" * 20 + "G := G + 2;\r\n"  # 21 line breaks
C_INC = "// c1\r\nG := G + 3;\r\n// c3"  # 2 line breaks, none at the end
D_INC = "// d1\r\n{$I A.inc}\r\nG := G + 4;\r\n// d4\r\n"  # 4 + 5 nested


def _lookup(files: dict[str, str]):
    def lookup(name: str, including: PurePath):
        text = files.get(name)
        return None if text is None else (including.parent / name, text)

    return lookup


def test_lines_up_to_32767_are_kept():
    line_map = PhysicalLineMap([(204, 5), (32764, 5)])

    assert line_map.logical_line(205) == 205
    assert line_map.logical_line(32767) == 32767


def test_physical_lines_past_32767():
    # Includes of A.inc (5 line breaks) at lines 204, 16004 and 32764 and of
    # B.inc (21) at 40004.
    text = _filler_unit(
        {204: "A.inc", 16004: "A.inc", 32764: "A.inc", 40004: "B.inc"}, 40200
    )
    line_map = physical_line_map(
        PurePath("T.pas"), text, _lookup({"A.inc": A_INC, "B.inc": B_INC}), {}
    )
    assert line_map is not None

    # Statements after the third include.
    assert line_map.logical_line(32780) == 32765
    assert line_map.logical_line(32809) == 32794
    assert line_map.logical_line(32869) == 32854
    # A.inc's statement at the third include is recorded under T.pas.
    assert line_map.logical_line(32777) == 32764
    # B.inc's statement, then the statements after it.
    assert line_map.logical_line(40039) == 40004
    assert line_map.logical_line(40041) == 40005
    assert line_map.logical_line(40140) == 40104


def test_physical_lines_count_line_breaks_and_nested_includes():
    # C.inc (2 line breaks) at 104 and 32854, D.inc (4, plus 5 of A.inc) at
    # 204 and 32954.
    text = _filler_unit(
        {104: "C.inc", 204: "D.inc", 32854: "C.inc", 32954: "D.inc"}, 33100
    )
    files = {"A.inc": A_INC, "C.inc": C_INC, "D.inc": D_INC}
    line_map = physical_line_map(PurePath("T.pas"), text, _lookup(files), {})
    assert line_map is not None

    assert line_map.logical_line(32805) == 32794
    assert line_map.logical_line(32866) == 32854
    assert line_map.logical_line(32868) == 32855
    assert line_map.logical_line(32917) == 32904
    # A.inc nested in D.inc, then D.inc's own statement, then the unit's.
    assert line_map.logical_line(32971) == 32954
    assert line_map.logical_line(32974) == 32954
    assert line_map.logical_line(32977) == 32955
    assert line_map.logical_line(33026) == 33004


def test_include_sites_skip_comments_switches_and_inactive_branches():
    text = dedent("""\
        {$I-}
        {$I First.inc}
        // {$I Commented.inc}
        (* {$I Commented.inc} *)
        {$IFDEF LBS_OPENGL}
        {$INCLUDE 'Inactive.inc'}
        {$ELSE}
        {$INCLUDE 'Active.inc'}
        {$ENDIF}
        S := '{$I NotAComment.inc}';
        {$IMPORTEDDATA ON}
        """)

    assert list(iter_include_sites(text, {"LBS_OPENGL": False})) == [
        (2, "First.inc"),
        (8, "Active.inc"),
    ]


def test_unreadable_include_leaves_the_lines():
    text = _filler_unit({10: "Missing.inc"}, 20)

    assert physical_line_map(PurePath("T.pas"), text, _lookup({}), {}) is None


def test_remap_delphi_physical_lines_finds_the_function():
    unit_path = PurePath("src/T.pas")
    lines = ["// filler"] * 32800
    lines[32764 - 1] = "  {$I A.inc}"
    lines[32791 - 1] = "procedure P9;"
    lines[32792 - 1] = "begin"
    lines[32794 - 1] = "  X := 1;"
    lines[32797 - 1] = "end;"
    code_files = [
        TextFile(unit_path, "\r\n".join(lines) + "\r\n"),
        TextFile(PurePath("src/A.inc"), A_INC),
    ]

    lines_db = LinesDb()
    lines_db.add_lines(
        PureWindowsPath("src\\T.pas"), [(32799, 0x1000), (32802, 0x1010)]
    )
    lines_db.mark_function_starts([0x1000])
    lines_db.add_local_paths(f.path for f in code_files)

    assert lines_db.find_function(unit_path, 32791, 32797) is None

    remap_delphi_physical_lines(code_files, lines_db, {})

    assert lines_db.find_function(unit_path, 32791, 32797) == 0x1000
    assert lines_db.find_line_of_recomp_address(0x1010) == (unit_path, 32797)
