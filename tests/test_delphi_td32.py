import logging
import struct
from pathlib import PureWindowsPath

from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey
from reccmp.delphi import DelphiTd32Analysis, DelphiTd32Parser, has_embedded_td32
from reccmp.delphi.td32 import (
    decode_td32_call_convention,
    extract_td32_stream,
    normalize_delphi_name,
)
from reccmp.project.common import RECCMP_BUILD_CONFIG, RECCMP_PROJECT_CONFIG
from reccmp.project.config import BuildFile
from reccmp.project.detect import DetectWhat, detect_project
from reccmp.types import EntityType


def _align4(data: bytearray):
    while len(data) % 4:
        data.append(0)


def _numeric(value: int) -> bytes:
    assert 0 <= value < 0x8000
    return struct.pack("<H", value)


def _type_record(leaf: int, payload: bytes) -> bytes:
    return struct.pack("<HH", len(payload) + 2, leaf) + payload


def _symbol_record(symbol_type: int, payload: bytes) -> bytes:
    return struct.pack("<HH", len(payload) + 2, symbol_type) + payload


def _names_subsection(names: list[str]) -> bytes:
    result = bytearray(struct.pack("<I", len(names)))
    for name in names:
        raw = name.encode()
        result += struct.pack("<B", len(raw) & 0xFF) + raw + b"\0"
    return bytes(result)


def _types_subsection(names: dict[str, int]) -> bytes:
    records = []

    field_payload = (
        struct.pack("<HIHI", 0x0406, CVInfoTypeEnum.T_INT4, 0, names["FieldA"])
        + struct.pack("<I", 0)
        + _numeric(0)
    )
    records.append(_type_record(0x0204, field_payload))

    struct_payload = (
        struct.pack("<HIHIII", 1, 0x1000, 0, 0, 0, 0)
        + struct.pack("<I", names["TWidget"])
        + _numeric(4)
    )
    records.append(_type_record(0x0005, struct_payload))

    array_payload = struct.pack(
        "<III", CVInfoTypeEnum.T_INT4, CVInfoTypeEnum.T_INT4, names["Numbers"]
    ) + _numeric(8)
    records.append(_type_record(0x0003, array_payload))

    arglist_payload = struct.pack("<H", 0)
    records.append(_type_record(0x0201, arglist_payload))

    proc_payload = (
        struct.pack("<I", CVInfoTypeEnum.T_VOID)
        + struct.pack("<BBH", 7, 0, 0)
        + struct.pack("<I", 0x1003)
    )
    records.append(_type_record(0x0008, proc_payload))

    pascal_array_payload = struct.pack(
        "<III", CVInfoTypeEnum.T_PASCHAR, CVInfoTypeEnum.T_INT4, names["PasChars"]
    ) + _numeric(4)
    records.append(_type_record(0x0032, pascal_array_payload))

    enum_field_payload = (
        struct.pack("<HhII", 0x0403, 0, names["fmCold"], 0)
        + _numeric(0)
        + struct.pack("<HhII", 0x0403, 0, names["fmWarm"], 0)
        + _numeric(1)
    )
    records.append(_type_record(0x0204, enum_field_payload))

    pascal_enum_payload = struct.pack("<HIII", 2, 0x10716103, 0x1006, 0) + struct.pack(
        "<I", names["TMode"]
    )
    records.append(_type_record(0x0007, pascal_enum_payload))

    unknown39_payload = struct.pack("<I", names["WideString"])
    records.append(_type_record(0x0039, unknown39_payload))

    records.append(_type_record(0x000A, b"\0\0"))
    records.append(_type_record(0x0207, struct.pack("<HII", 0, 0x1004, 0)))
    records.append(_type_record(0x0035, b"\0" * 22))
    mfunction_payload = (
        struct.pack(
            "<III",
            CVInfoTypeEnum.T_VOID,
            0x1001,
            CVInfoTypeEnum.T_32PVOID,
        )
        + struct.pack("<BBH", 12, 0, 0)
        + struct.pack("<Ii", 0x1003, 0)
    )
    records.append(_type_record(0x0009, mfunction_payload))

    header_size = 4 + 4 * len(records)
    result = bytearray(struct.pack("<I", len(records)))
    offsets = []
    cursor = header_size
    for record in records:
        offsets.append(cursor)
        cursor += len(record)
        while cursor % 4:
            cursor += 1

    for offset in offsets:
        result += struct.pack("<I", offset)

    for record in records:
        result += record
        _align4(result)

    return bytes(result)


def _symbols_subsection(names: dict[str, int]) -> bytes:
    result = bytearray(struct.pack("<I", 0))

    proc_payload = (
        struct.pack("<III", 0, 0, 0)
        + struct.pack("<III", 0x30, 0, 0x30)
        + struct.pack("<IHHII", 0x10, 1, 0, 0x1004, names["Click"])
        + struct.pack("<I", 0)
    )
    result += _symbol_record(0x0205, proc_payload)

    bprel_payload = (
        struct.pack("<iI", -4, CVInfoTypeEnum.T_INT4)
        + struct.pack("<I", names["LocalValue"])
        + struct.pack("<I", 0)
    )
    result += _symbol_record(0x0200, bprel_payload)

    register_payload = (
        struct.pack("<IH", CVInfoTypeEnum.T_32PVOID, 23)
        + struct.pack("<I", names["Self"])
        + struct.pack("<I", 0)
    )
    result += _symbol_record(0x0002, register_payload)
    result += _symbol_record(0x0006, b"")

    global_payload = struct.pack(
        "<IHHII", 0x20, 2, 0, 0x1001, names["GlobalValue"]
    ) + struct.pack("<I", 0)
    result += _symbol_record(0x0202, global_payload)

    vmt_payload = struct.pack(
        "<IHHII", 0x40, 2, 0, CVInfoTypeEnum.T_32PVOID, names["Vmt"]
    ) + struct.pack("<I", 0)
    result += _symbol_record(0x0203, vmt_payload)

    return bytes(result)


def _source_subsection(names: dict[str, int]) -> bytes:
    file_offset = 20
    line_offset = 40
    result = bytearray(
        struct.pack("<HHI", 1, 1, file_offset)
        + struct.pack("<II", 0x10, 0x40)
        + struct.pack("<H", 1)
        + b"\0\0"
    )
    assert len(result) == file_offset
    result += (
        struct.pack("<HII", 1, names["Unit1.pas"], line_offset)
        + struct.pack("<II", 0x10, 0x40)
        + b"\0\0"
    )
    assert len(result) == line_offset
    result += (
        struct.pack("<HH", 1, 2)
        + struct.pack("<II", 0x10, 0x20)
        + struct.pack("<HH", 12, 14)
    )
    return bytes(result)


def build_td32_stream() -> bytes:
    names_list = [
        "C:\\src\\Unit1.pas",
        "@Unit1@TWidget@Click$qqrv",
        "LocalValue",
        "GlobalValue",
        "@Unit1@TWidget@$vmt",
        "TWidget",
        "FieldA",
        "Numbers",
        "Self",
        "PasChars",
        "fmCold",
        "fmWarm",
        "TMode",
        "WideString",
    ]
    names = {
        "Unit1.pas": 1,
        "Click": 2,
        "LocalValue": 3,
        "GlobalValue": 4,
        "Vmt": 5,
        "TWidget": 6,
        "FieldA": 7,
        "Numbers": 8,
        "Self": 9,
        "PasChars": 10,
        "fmCold": 11,
        "fmWarm": 12,
        "TMode": 13,
        "WideString": 14,
    }
    subsections = [
        (0x0130, 0, _names_subsection(names_list)),
        (0x012B, 0, _types_subsection(names)),
        (0x0125, 1, _symbols_subsection(names)),
        (0x0127, 1, _source_subsection(names)),
    ]

    stream = bytearray(b"FB09" + b"\0\0\0\0")
    entries = []
    for subsection_type, module_index, payload in subsections:
        _align4(stream)
        offset = len(stream)
        stream += payload
        entries.append((subsection_type, module_index, offset, len(payload)))

    _align4(stream)
    directory_offset = len(stream)
    stream[4:8] = struct.pack("<I", directory_offset)
    stream += struct.pack("<HHIII", 16, 12, len(entries), 0, 0)
    for entry in entries:
        stream += struct.pack("<HHII", *entry)

    stream += b"FB09" + struct.pack("<I", len(stream) + 8)
    return bytes(stream)


def test_extract_td32_stream_from_appended_data():
    stream = build_td32_stream()

    assert extract_td32_stream(b"not a pe" + stream) == stream


def test_delphi_td32_parser_reads_symbols_lines_and_types():
    parser = DelphiTd32Parser.from_bytes(build_td32_stream())

    assert parser.lines[PureWindowsPath("C:\\src\\Unit1.pas")] == [
        (12, 1, 0x10),
        (14, 1, 0x20),
    ]
    assert [symbol.name for symbol in parser.symbols] == ["Unit1.TWidget.Click"]
    assert parser.symbols[0].symbols[0].location == "[FFFFFFFC]"
    assert parser.symbols[0].symbols[0].name == "LocalValue"
    assert parser.symbols[0].symbols[1].location == "esi"
    assert parser.globals[0].name == "GlobalValue"
    assert "@Unit1@TWidget@$vmt" in [public.name for public in parser.publics]

    record_type = parser.types.get(CvdumpTypeKey(0x1001))
    assert record_type.size == 4
    assert record_type.members == [
        (0, "FieldA", CVInfoTypeEnum.T_INT4),
    ]

    array_type = parser.types.get(CvdumpTypeKey(0x1002))
    assert array_type.size == 8
    assert len(array_type.members or []) == 2

    pascal_array_type = parser.types.get(CvdumpTypeKey(0x1005))
    assert pascal_array_type.size == 4
    assert [member.type for member in pascal_array_type.members or []] == [
        CVInfoTypeEnum.T_RCHAR,
        CVInfoTypeEnum.T_RCHAR,
        CVInfoTypeEnum.T_RCHAR,
        CVInfoTypeEnum.T_RCHAR,
    ]

    enum_obj = parser.types.keys[CvdumpTypeKey(0x1007)]
    assert enum_obj["underlying_type"] == CVInfoTypeEnum.T_INT4
    assert enum_obj["field_list_type"] == CvdumpTypeKey(0x1006)
    assert parser.types.get(CvdumpTypeKey(0x1007)).size == 4
    assert parser.types.get(CvdumpTypeKey(0x1008)).size == 4
    assert not ({0x000A, 0x0035, 0x0039, 0x0207} & parser.unhandled_types)


def test_decode_td32_call_conventions():
    assert decode_td32_call_convention(0).name == "Near C"
    assert decode_td32_call_convention(2).name == "Near Pascal"
    assert decode_td32_call_convention(4).name == "Near Fast"
    assert decode_td32_call_convention(7).name == "Near Std"
    assert decode_td32_call_convention(11).name == "ThisCall"

    borland_register = decode_td32_call_convention(12)
    assert borland_register.raw_value == 12
    assert borland_register.base_value == 12
    assert borland_register.fastthis is False
    assert borland_register.name == "Borland Register"

    fastthis = decode_td32_call_convention(0x84)
    assert fastthis.raw_value == 0x84
    assert fastthis.base_value == 4
    assert fastthis.fastthis is True
    assert fastthis.name == "Near Fast"

    unknown = decode_td32_call_convention(0x8D)
    assert unknown.raw_value == 0x8D
    assert unknown.base_value == 13
    assert unknown.fastthis is True
    assert unknown.name == "CallConv 141"


def test_delphi_td32_parser_preserves_call_convention_metadata():
    parser = DelphiTd32Parser.from_bytes(build_td32_stream())

    procedure_type = parser.types.keys[CvdumpTypeKey(0x1004)]
    assert procedure_type["call_type"] == "Near Std"
    assert procedure_type["call_type_info"] == {
        "raw_value": 7,
        "base_value": 7,
        "fastthis": False,
        "name": "Near Std",
    }

    method_type = parser.types.keys[CvdumpTypeKey(0x100C)]
    assert method_type["call_type"] == "Borland Register"
    assert method_type["call_type_info"] == {
        "raw_value": 12,
        "base_value": 12,
        "fastthis": False,
        "name": "Borland Register",
    }


def test_delphi_td32_analysis_creates_reccmp_nodes():
    analysis = DelphiTd32Analysis.from_bytes(build_td32_stream())

    functions = [
        node for node in analysis.nodes if node.node_type == EntityType.FUNCTION
    ]
    assert len(functions) == 1
    assert functions[0].friendly_name == "Unit1.TWidget.Click"
    assert functions[0].confirmed_size == 0x30
    assert functions[0].symbol_entry is not None
    assert functions[0].symbol_entry.symbols[0].name == "LocalValue"

    data_nodes = [node for node in analysis.nodes if node.node_type == EntityType.DATA]
    assert data_nodes[0].friendly_name == "GlobalValue"
    assert data_nodes[0].data_type is not None
    assert data_nodes[0].data_type.key == CvdumpTypeKey(0x1001)

    vtables = [node for node in analysis.nodes if node.node_type == EntityType.VTABLE]
    assert len(vtables) == 1
    assert vtables[0].friendly_name == "Unit1.TWidget"


def test_normalize_delphi_name():
    assert normalize_delphi_name("@Unit1@TWidget@Click$qqrv") == "Unit1.TWidget.Click"


def test_project_detect_uses_binary_when_it_has_embedded_td32(tmp_path):
    project_text = """\
targets:
  TEST:
    filename: TEST.EXE
    source-root: sources
    hash:
      sha256: unused
"""
    project_root = tmp_path / "project"
    build_dir = tmp_path / "build"
    project_root.mkdir()
    build_dir.mkdir()
    (project_root / "sources").mkdir()
    (project_root / RECCMP_PROJECT_CONFIG).write_text(project_text)

    binary = build_dir / "TEST.EXE"
    binary.write_bytes(b"prefix" + build_td32_stream())

    detect_project(
        project_directory=project_root,
        search_path=[build_dir],
        detect_what=DetectWhat.RECOMPILED,
        build_directory=project_root,
    )

    build = BuildFile.from_file(project_root / RECCMP_BUILD_CONFIG)
    assert build.targets["TEST"].path == binary
    assert build.targets["TEST"].pdb == binary
    assert has_embedded_td32(binary)


def test_known_ignored_td32_symbol_types_do_not_log_unhandled(caplog):
    parser = DelphiTd32Parser()

    with caplog.at_level(logging.INFO):
        parser._parse_symbol_record(0x0208, b"")
        parser._parse_symbol_record(0x0211, b"")

    assert "Unhandled TD32 symbol type" not in caplog.text
    assert not ({0x0208, 0x0211} & parser.unhandled_symbols)


def test_known_ignored_td32_type_leaf_does_not_log_unhandled(caplog):
    parser = DelphiTd32Parser()

    with caplog.at_level(logging.INFO):
        assert parser._parse_type_record(CvdumpTypeKey(0x1000), 0x0034, b"") is None

    assert "Unhandled TD32 type leaf" not in caplog.text
    assert 0x0034 not in parser.unhandled_types
