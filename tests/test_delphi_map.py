from pathlib import PureWindowsPath

from reccmp.delphi import DelphiMapAnalysis, DelphiMapParser
from reccmp.types import EntityType

MAP_TEXT = """\
 Start         Length      Name                   Class
 0001:00401000 00000100H .text                   CODE
 0002:00423000 00000020H .data                   DATA

 Address Publics by Value

 0001:00000010       Unit1.TForm1.ButtonClick
 0001:00000040       Unit1.Helper
 0002:00000004       Unit1.GlobalValue

 Line numbers for Unit1(C:\\src\\Unit1.pas) segment Unit1

   12 0001:00000010    13 0001:00000016    20 0001:00000040
"""


def test_delphi_map_parser_reads_publics_and_lines():
    parser = DelphiMapParser()
    parser.read(MAP_TEXT)

    assert parser.section_classes == {1: "CODE", 2: "DATA"}
    assert [public.name for public in parser.publics] == [
        "Unit1.TForm1.ButtonClick",
        "Unit1.Helper",
        "Unit1.GlobalValue",
    ]
    assert parser.lines[PureWindowsPath("C:\\src\\Unit1.pas")][0].line_number == 12
    assert parser.lines[PureWindowsPath("C:\\src\\Unit1.pas")][0].section == 1
    assert parser.lines[PureWindowsPath("C:\\src\\Unit1.pas")][0].offset == 0x10


def test_delphi_map_analysis_creates_reccmp_nodes():
    analysis = DelphiMapAnalysis.from_text(MAP_TEXT)

    assert len(analysis.nodes) == 3
    assert analysis.nodes[0].friendly_name == "Unit1.TForm1.ButtonClick"
    assert analysis.nodes[0].node_type == EntityType.FUNCTION
    assert analysis.nodes[0].estimated_size == 0x30
    assert analysis.nodes[2].friendly_name == "Unit1.GlobalValue"
    assert analysis.nodes[2].node_type == EntityType.DATA
