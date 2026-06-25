"""Reader for embedded Borland/Delphi TD32 debug information.

The Delphi 7 compiler stores TD32 data in an FB09/FB0A stream. The stream may
be the whole file, appended to the image, or referenced by an UNKNOWN PE debug
directory entry.  The parser below translates the pieces reccmp uses into the
same structures populated by the cvdump/PDB path.
"""

# pylint: disable=too-many-lines,too-many-instance-attributes,too-many-return-statements

from __future__ import annotations

from dataclasses import dataclass
import logging
from pathlib import Path, PureWindowsPath
import struct
from typing import NamedTuple, cast

from reccmp.cvdump.analysis import CvdumpAnalysis, CvdumpNode
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey
from reccmp.cvdump.cvinfo import CvdumpTypeMap
from reccmp.cvdump.parser import (
    GdataEntry,
    LineValue,
    PublicsEntry,
    SizeRefEntry,
)
from reccmp.cvdump.symbols import LdataEntry, StackOrRegisterSymbol, SymbolsEntry
from reccmp.cvdump.types import (
    CvdumpCallConvention,
    CvdumpKeyError,
    CvdumpIntegrityError,
    CvdumpTypesParser,
    CvdumpParsedType,
    EnumItem,
    FieldListItem,
    VirtualBaseClass,
    VirtualBasePointer,
)
from reccmp.formats import PEImage, detect_image
from reccmp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.formats.pe import DebugDirectoryEntryHeader, PEDataDirectoryItemType
from reccmp.types import EntityType

logger = logging.getLogger(__name__)

TD32_SIGNATURES = (b"FB09", b"FB0A")

SUBSECTION_TYPE_MODULE = 0x0120
SUBSECTION_TYPE_ALIGN_SYMBOLS = 0x0125
SUBSECTION_TYPE_SOURCE_MODULE = 0x0127
SUBSECTION_TYPE_GLOBAL_SYMBOLS = 0x0129
SUBSECTION_TYPE_GLOBAL_TYPES = 0x012B
SUBSECTION_TYPE_NAMES = 0x0130

SYMBOL_TYPE_REGISTER = 0x0002
SYMBOL_TYPE_END = 0x0006
SYMBOL_TYPE_GPROCREF = 0x0020
SYMBOL_TYPE_GDATAREF = 0x0021
SYMBOL_TYPES_IGNORED = {
    0x0001,
    0x0004,
    0x0005,
    0x0024,
    0x0025,
    0x0026,
    0x0027,
    0x0208,
    0x0211,
    0x0230,
}
SYMBOL_TYPE_BPREL32 = 0x0200
SYMBOL_TYPE_LDATA32 = 0x0201
SYMBOL_TYPE_GDATA32 = 0x0202
SYMBOL_TYPE_PUB32 = 0x0203
SYMBOL_TYPE_LPROC32 = 0x0204
SYMBOL_TYPE_GPROC32 = 0x0205
SYMBOL_TYPE_BLOCK32 = 0x0207
SYMBOL_TYPE_VFTPATH32 = 0x020B

TYPE_LF_MODIFIER = 0x0001
TYPE_LF_POINTER = 0x0002
TYPE_LF_ARRAY = 0x0003
TYPE_LF_CLASS = 0x0004
TYPE_LF_STRUCTURE = 0x0005
TYPE_LF_UNION = 0x0006
TYPE_LF_ENUM = 0x0007
TYPE_LF_PROCEDURE = 0x0008
TYPE_LF_MFUNCTION = 0x0009
TYPE_LF_VTSHAPE = 0x000A
TYPE_PAS_SET = 0x0030
TYPE_PAS_SUBRANGE = 0x0031
TYPE_PAS_PARRAY = 0x0032
TYPE_PAS_PSTRING = 0x0033
TYPE_PAS_UNKNOWN34 = 0x0034
TYPE_PAS_PROPERTY = 0x0035
TYPE_PAS_LSTRING = 0x0036
TYPE_PAS_VARIANT = 0x0037
TYPE_PAS_CLASSREF = 0x0038
TYPE_PAS_UNKNOWN39 = 0x0039
TYPE_LF_ARGLIST = 0x0201
TYPE_LF_FIELDLIST = 0x0204
TYPE_LF_BITFIELD = 0x0206
TYPE_LF_MLIST = 0x0207
TYPE_LF_BCLASS = 0x0400
TYPE_LF_VBCLASS = 0x0401
TYPE_LF_IVBCLASS = 0x0402
TYPE_LF_ENUMERATE = 0x0403
TYPE_LF_INDEX = 0x0405
TYPE_LF_MEMBER = 0x0406
TYPE_LF_STMEMBER = 0x0407
TYPE_LF_METHOD = 0x0408
TYPE_LF_NESTTYPE = 0x0409
TYPE_LF_VFUNCTAB = 0x040A

REGISTER_NAMES = {
    1: "al",
    2: "cl",
    3: "dl",
    4: "bl",
    5: "ah",
    6: "ch",
    7: "dh",
    8: "bh",
    9: "ax",
    10: "cx",
    11: "dx",
    12: "bx",
    13: "sp",
    14: "bp",
    15: "si",
    16: "di",
    17: "eax",
    18: "ecx",
    19: "edx",
    20: "ebx",
    21: "esp",
    22: "ebp",
    23: "esi",
    24: "edi",
}

TYPE_NAMES = {
    TYPE_LF_MODIFIER: "LF_MODIFIER",
    TYPE_LF_POINTER: "LF_POINTER",
    TYPE_LF_ARRAY: "LF_ARRAY",
    TYPE_LF_CLASS: "LF_CLASS",
    TYPE_LF_STRUCTURE: "LF_STRUCTURE",
    TYPE_LF_UNION: "LF_UNION",
    TYPE_LF_ENUM: "LF_ENUM",
    TYPE_LF_PROCEDURE: "LF_PROCEDURE",
    TYPE_LF_MFUNCTION: "LF_MFUNCTION",
    TYPE_LF_ARGLIST: "LF_ARGLIST",
    TYPE_LF_FIELDLIST: "LF_FIELDLIST",
    TYPE_LF_BITFIELD: "LF_BITFIELD",
}


class DelphiTd32Error(ValueError):
    """Raised when data is not a supported TD32 stream."""


class Td32Vtable(NamedTuple):
    section: int
    offset: int
    root_type: CvdumpTypeKey
    path_type: CvdumpTypeKey


@dataclass(frozen=True)
class Td32CallConvention:
    raw_value: int
    base_value: int
    fastthis: bool
    name: str

    def as_cvdump(self) -> CvdumpCallConvention:
        return {
            "raw_value": self.raw_value,
            "base_value": self.base_value,
            "fastthis": self.fastthis,
            "name": self.name,
        }


@dataclass(frozen=True)
class DirectoryEntry:
    subsection_type: int
    module_index: int
    offset: int
    size: int


class BinaryReader:
    """Small bounds-checked little-endian reader for TD32 records."""

    def __init__(self, data: bytes, offset: int = 0, end: int | None = None):
        self.data = data
        self.offset = offset
        self.end = len(data) if end is None else end

    def remaining(self) -> int:
        return self.end - self.offset

    def seek(self, offset: int):
        if offset < 0 or offset > self.end:
            raise DelphiTd32Error(f"Read outside TD32 record: {offset}")
        self.offset = offset

    def skip(self, count: int):
        self.seek(self.offset + count)

    def _unpack(self, fmt: str) -> tuple[int, ...]:
        size = struct.calcsize(fmt)
        if self.offset + size > self.end:
            raise DelphiTd32Error("Unexpected end of TD32 data")
        values = struct.unpack_from(fmt, self.data, self.offset)
        self.offset += size
        return values

    def u8(self) -> int:
        return self._unpack("<B")[0]

    def i8(self) -> int:
        return self._unpack("<b")[0]

    def u16(self) -> int:
        return self._unpack("<H")[0]

    def i16(self) -> int:
        return self._unpack("<h")[0]

    def u32(self) -> int:
        return self._unpack("<I")[0]

    def i32(self) -> int:
        return self._unpack("<i")[0]


def _read_u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise DelphiTd32Error("Unexpected end of TD32 data")
    return struct.unpack_from("<I", data, offset)[0]


def _is_td32_signature(value: bytes) -> bool:
    return value in TD32_SIGNATURES


def _is_valid_td32_stream(data: bytes) -> bool:
    if len(data) < 24 or not _is_td32_signature(data[:4]):
        return False

    try:
        directory_offset = _read_u32(data, 4)
        if directory_offset <= 0 or directory_offset + 16 > len(data):
            return False

        size, entry_size, entry_count = struct.unpack_from(
            "<HHI", data, directory_offset
        )
        if size != 16 or entry_size != 12:
            return False

        entries_end = directory_offset + size + entry_count * entry_size
        return entries_end <= len(data)
    except (struct.error, DelphiTd32Error):
        return False


def decode_td32_call_convention(value: int) -> Td32CallConvention:
    """Decode a Borland TD32 LF_PROCEDURE/LF_MFUNCTION call-convention byte."""

    fastthis = bool(value & 0x80)
    base_value = value & 0x7F

    # Borland's 1993 TD32 documentation reserves 12-255. Delphi 7 embedded
    # TD32 uses 12 for its default Win32 register convention in real fixtures.
    name = {
        0: "Near C",
        2: "Near Pascal",
        4: "Near Fast",
        7: "Near Std",
        11: "ThisCall",
        12: "Borland Register",
    }.get(base_value, f"CallConv {value}")

    return Td32CallConvention(
        raw_value=value,
        base_value=base_value,
        fastthis=fastthis,
        name=name,
    )


def extract_td32_stream(data: bytes) -> bytes:
    """Return the TD32 stream from raw bytes or appended-image bytes."""

    if _is_valid_td32_stream(data):
        return data

    if len(data) >= 8 and _is_td32_signature(data[-8:-4]):
        td32_size = _read_u32(data, len(data) - 4)
        base = len(data) - td32_size
        if 0 <= base < len(data) and _is_valid_td32_stream(data[base:]):
            return data[base:]

    raise DelphiTd32Error("No embedded TD32 debug information found")


def extract_td32_stream_from_pe(image: PEImage) -> bytes:
    """Return TD32 data from a PE image, including UNKNOWN debug-directory data."""

    try:
        return extract_td32_stream(image.data)
    except DelphiTd32Error:
        pass

    debug_directory = image.get_data_directory_region(PEDataDirectoryItemType.DEBUG)
    if debug_directory is None:
        raise DelphiTd32Error("No embedded TD32 debug information found")

    debug_entry_data = image.read(
        debug_directory.virtual_address, debug_directory.virtual_size
    )
    offset = 0
    while offset + 28 <= len(debug_entry_data):
        debug_entry, offset = DebugDirectoryEntryHeader.from_memory(
            debug_entry_data, offset=offset
        )
        start = debug_entry.pointer_to_raw_data
        end = start + debug_entry.size_of_data
        if start < 0 or end > len(image.data):
            continue

        try:
            return extract_td32_stream(image.data[start:end])
        except DelphiTd32Error:
            continue

    raise DelphiTd32Error("No embedded TD32 debug information found")


def has_embedded_td32(path: Path) -> bool:
    """Cheap feature test used by project detection."""

    try:
        data = path.read_bytes()
        extract_td32_stream(data)
        return True
    except (OSError, DelphiTd32Error):
        pass

    try:
        image = detect_image(path)
    except (OSError, ValueError, struct.error):
        return False

    if not isinstance(image, PEImage):
        return False

    try:
        extract_td32_stream_from_pe(image)
        return True
    except DelphiTd32Error:
        return False


def normalize_delphi_name(name: str | None) -> str | None:
    """Normalize Delphi TD32 names without attempting full C++ demangling."""

    if name is None:
        return None

    result = name.strip()
    if result.startswith("@"):
        parts = [part for part in result.split("@") if part]
        if parts:
            result = ".".join(parts)

    if "$" in result and not result.startswith("$"):
        result = result.split("$", 1)[0]

    return result.rstrip(".")


def delphi_vmt_class_name(name: str | None) -> str | None:
    """Return the class name if a TD32 symbol name looks like a Delphi VMT."""

    if not name:
        return None

    raw = name.strip()
    lowered = raw.lower()
    for marker in ("$vmt", "@vmt", ".vmt"):
        marker_index = lowered.find(marker)
        if marker_index != -1:
            return normalize_delphi_name(raw[:marker_index])

    normalized = normalize_delphi_name(raw)
    if normalized is not None and normalized.lower().endswith(".vmt"):
        return normalized[:-4]

    return None


class DelphiTd32Parser:
    """Parse enough TD32 data to feed reccmp's existing PDB workflows."""

    def __init__(self) -> None:
        self.names: list[str | None] = [None]
        self.modules: list[DirectoryEntry] = []
        self.lines: dict[PureWindowsPath, list[LineValue]] = {}
        self.publics: list[PublicsEntry] = []
        self.sizerefs: list[SizeRefEntry] = []
        self.globals: list[GdataEntry] = []
        self.symbols: list[SymbolsEntry] = []
        self.types = CvdumpTypesParser()
        self.vtables: list[Td32Vtable] = []
        self.unhandled_subsections: set[int] = set()
        self.unhandled_symbols: set[int] = set()
        self.unhandled_types: set[int] = set()

        self._current_function: SymbolsEntry | None = None
        self._block_level = 0
        self._seen_publics: set[tuple[int, int, str]] = set()

    @classmethod
    def from_bytes(cls, data: bytes) -> "DelphiTd32Parser":
        parser = cls()
        parser.read(data)
        return parser

    @classmethod
    def from_file(cls, path: Path) -> "DelphiTd32Parser":
        return cls.from_bytes(path.read_bytes())

    def name(self, name_index: int) -> str | None:
        if name_index <= 0 or name_index >= len(self.names):
            return None

        return self.names[name_index]

    def type_name(self, type_key: CvdumpTypeKey) -> str | None:
        type_obj = self.types.keys.get(type_key)
        if type_obj is None:
            return None

        return type_obj.get("name")

    def read(self, data: bytes):
        stream = extract_td32_stream(data)
        entries = self._read_directory(stream)

        for entry in entries:
            if entry.subsection_type == SUBSECTION_TYPE_NAMES:
                self._read_names(self._subsection(stream, entry))

        for entry in entries:
            if entry.subsection_type == SUBSECTION_TYPE_GLOBAL_TYPES:
                self._read_global_types(self._subsection(stream, entry))

        for entry in entries:
            if entry.subsection_type == SUBSECTION_TYPE_MODULE:
                self.modules.append(entry)

        for entry in entries:
            subsection = self._subsection(stream, entry)
            if entry.subsection_type == SUBSECTION_TYPE_SOURCE_MODULE:
                self._read_source_module(subsection)
            elif entry.subsection_type == SUBSECTION_TYPE_ALIGN_SYMBOLS:
                self._read_symbols(subsection, has_signature=True)
            elif entry.subsection_type == SUBSECTION_TYPE_GLOBAL_SYMBOLS:
                self._read_global_symbols(subsection)
            elif entry.subsection_type not in (
                SUBSECTION_TYPE_NAMES,
                SUBSECTION_TYPE_GLOBAL_TYPES,
                SUBSECTION_TYPE_MODULE,
            ):
                self._log_unhandled_subsection(entry.subsection_type)

    def _subsection(self, stream: bytes, entry: DirectoryEntry) -> bytes:
        end = entry.offset + entry.size
        if entry.offset < 0 or end > len(stream):
            raise DelphiTd32Error(
                f"TD32 subsection 0x{entry.subsection_type:x} outside stream"
            )

        return stream[entry.offset : end]

    def _read_directory(self, stream: bytes) -> list[DirectoryEntry]:
        directory_offset = _read_u32(stream, 4)
        entries: list[DirectoryEntry] = []

        while directory_offset:
            reader = BinaryReader(stream, directory_offset)
            header_size = reader.u16()
            entry_size = reader.u16()
            entry_count = reader.u32()
            next_directory = reader.u32()
            reader.u32()  # flags

            if header_size != 16 or entry_size != 12:
                raise DelphiTd32Error("Unsupported TD32 directory layout")

            for _ in range(entry_count):
                entries.append(
                    DirectoryEntry(
                        subsection_type=reader.u16(),
                        module_index=reader.u16(),
                        offset=reader.u32(),
                        size=reader.u32(),
                    )
                )

            directory_offset = next_directory

        return entries

    def _read_names(self, data: bytes):
        if len(data) < 4:
            return

        reader = BinaryReader(data)
        count = reader.u32()
        self.names = [None]

        for _ in range(count):
            if reader.remaining() <= 0:
                break

            nominal_length = reader.u8()
            start = reader.offset
            try:
                end = data.index(0, start)
            except ValueError:
                end = min(start + nominal_length, len(data))

            self.names.append(data[start:end].decode("utf-8", errors="replace"))
            reader.seek(min(end + 1, len(data)))

    def _read_global_types(self, data: bytes):
        layout = self._choose_global_type_layout(data)
        if layout is None:
            return

        count, offsets_start = layout
        offsets = [
            struct.unpack_from("<I", data, offsets_start + i * 4)[0]
            for i in range(count)
        ]

        for type_index, record_offset in enumerate(offsets):
            type_key = CvdumpTypeKey(0x1000 + type_index)
            if record_offset + 4 > len(data):
                continue

            length, leaf = struct.unpack_from("<HH", data, record_offset)
            record_end = record_offset + 2 + length
            if length < 2 or record_end > len(data):
                continue

            payload = data[record_offset + 4 : record_end]
            type_obj = self._parse_type_record(type_key, leaf, payload)
            if type_obj is not None:
                self.types.keys[type_key] = cast(CvdumpParsedType, type_obj)

    def _choose_global_type_layout(self, data: bytes) -> tuple[int, int] | None:
        candidates: list[tuple[int, int, int]] = []
        for count_offset in (0, 4):
            if count_offset + 4 > len(data):
                continue

            count = struct.unpack_from("<I", data, count_offset)[0]
            offsets_start = count_offset + 4
            offsets_end = offsets_start + count * 4
            if count > 0x100000 or offsets_end > len(data):
                continue

            offsets = [
                struct.unpack_from("<I", data, offsets_start + i * 4)[0]
                for i in range(count)
            ]
            valid_offsets = sum(
                1
                for offset in offsets
                if offsets_end <= offset and offset + 4 <= len(data)
            )
            if count in (0, valid_offsets):
                candidates.append((valid_offsets, count, offsets_start))

        if not candidates:
            return None

        _, count, offsets_start = max(candidates)
        return count, offsets_start

    def _parse_type_record(
        self, type_key: CvdumpTypeKey, leaf: int, payload: bytes
    ) -> dict | None:
        reader = BinaryReader(payload)

        try:
            if leaf == TYPE_LF_MODIFIER:
                reader.u16()  # attributes
                return {
                    "type": "LF_MODIFIER",
                    "is_forward_ref": True,
                    "modifies": self._read_type_key(reader),
                }

            if leaf == TYPE_LF_POINTER:
                reader.u16()  # pointer attributes
                return {
                    "type": "LF_POINTER",
                    "element_type": self._read_type_key(reader),
                    "pointer_type": "Pointer",
                }

            if leaf == TYPE_LF_ARRAY:
                array_type = self._normalize_pascal_array_element_type(
                    self._read_type_key(reader)
                )
                reader.u32()  # index type
                name = self.name(reader.u32())
                return {
                    "type": "LF_ARRAY",
                    "array_type": array_type,
                    "name": normalize_delphi_name(name),
                    "size": self._read_numeric(reader),
                }

            if leaf in (TYPE_LF_CLASS, TYPE_LF_STRUCTURE):
                return self._read_class_or_struct_type(reader, leaf)

            if leaf == TYPE_LF_UNION:
                reader.u16()  # member count
                field_list_type = self._read_type_key(reader)
                flags = reader.u16()
                reader.u32()  # containing type
                name = self.name(reader.u32())
                result = {
                    "type": "LF_UNION",
                    "field_list_type": field_list_type,
                    "name": normalize_delphi_name(name),
                    "size": self._read_numeric(reader),
                }
                if flags & 0x80:
                    result["is_forward_ref"] = True
                return result

            if leaf == TYPE_LF_ENUM:
                member_count = reader.u16()
                underlying_type = self._read_type_key(reader)
                field_list_type = self._read_type_key(reader)
                reader.u32()  # containing class
                name = self.name(reader.u32())
                if not self._is_type_key_resolvable(underlying_type):
                    underlying_type = CVInfoTypeEnum.T_INT4
                return {
                    "type": "LF_ENUM",
                    "num_members": member_count,
                    "underlying_type": underlying_type,
                    "field_list_type": field_list_type,
                    "name": normalize_delphi_name(name),
                }

            if leaf == TYPE_LF_PROCEDURE:
                return_type = self._read_type_key(reader)
                call_type = self._read_call_type(reader.u8())
                reader.u8()  # reserved
                num_params = reader.u16()
                arg_list_type = self._read_type_key(reader)
                return {
                    "type": "LF_PROCEDURE",
                    "return_type": return_type,
                    "call_type": call_type.name,
                    "call_type_info": call_type.as_cvdump(),
                    "func_attr": "",
                    "num_params": num_params,
                    "arg_list_type": arg_list_type,
                }

            if leaf == TYPE_LF_MFUNCTION:
                return_type = self._read_type_key(reader)
                class_type = self._read_type_key(reader)
                this_type = self._read_type_key(reader)
                call_type = self._read_call_type(reader.u8())
                reader.u8()  # reserved
                num_params = reader.u16()
                arg_list_type = self._read_type_key(reader)
                this_adjust = reader.i32()
                return {
                    "type": "LF_MFUNCTION",
                    "return_type": return_type,
                    "class_type": class_type,
                    "this_type": this_type,
                    "call_type": call_type.name,
                    "call_type_info": call_type.as_cvdump(),
                    "func_attr": "",
                    "num_params": num_params,
                    "arg_list_type": arg_list_type,
                    "this_adjust": this_adjust,
                }

            if leaf == TYPE_LF_VTSHAPE:
                reader.offset = reader.end
                return {"type": "LF_VTSHAPE"}

            if leaf in (TYPE_PAS_SET, TYPE_PAS_PARRAY):
                return self._read_pascal_array_type(reader, leaf)

            if leaf == TYPE_PAS_SUBRANGE:
                base_type = self._read_type_key(reader)
                name = normalize_delphi_name(self.name(reader.u32()))
                reader.offset = reader.end
                return {
                    "type": "LF_MODIFIER",
                    "is_forward_ref": True,
                    "modifies": base_type,
                    "name": name,
                }

            if leaf in (TYPE_PAS_PSTRING, TYPE_PAS_LSTRING, TYPE_PAS_CLASSREF):
                return {"type": "LF_POINTER", "element_type": CVInfoTypeEnum.T_VOID}

            if leaf == TYPE_PAS_UNKNOWN34:
                reader.offset = reader.end
                return None

            if leaf == TYPE_PAS_PROPERTY:
                reader.offset = reader.end
                return {"type": "LF_PROPERTY"}

            if leaf == TYPE_PAS_VARIANT:
                name = normalize_delphi_name(self.name(reader.u32()))
                return self._opaque_byte_array(name, 16)

            if leaf == TYPE_PAS_UNKNOWN39:
                name = normalize_delphi_name(self.name(reader.u32()))
                return {
                    "type": "LF_POINTER",
                    "element_type": CVInfoTypeEnum.T_VOID,
                    "name": name,
                }

            if leaf == TYPE_LF_ARGLIST:
                argcount = reader.u16()
                args = [self._read_type_key(reader) for _ in range(argcount)]
                result = {"type": "LF_ARGLIST", "argcount": argcount}
                if args:
                    result["args"] = args
                return result

            if leaf == TYPE_LF_FIELDLIST:
                return self._read_field_list(reader)

            if leaf == TYPE_LF_BITFIELD:
                bit_count = reader.u8()
                bit_start = reader.u8()
                bit_type = self._read_type_key(reader)
                return {
                    "type": "LF_BITFIELD",
                    "bit_count": bit_count,
                    "bit_start": bit_start,
                    "bit_type": bit_type,
                }

            if leaf == TYPE_LF_MLIST:
                reader.offset = reader.end
                return {"type": "LF_MLIST"}

        except DelphiTd32Error:
            logger.debug("Failed to parse TD32 type 0x%04x leaf 0x%04x", type_key, leaf)
            return None

        self._log_unhandled_type(leaf)
        return None

    def _read_class_or_struct_type(self, reader: BinaryReader, leaf: int) -> dict:
        reader.u16()  # member count
        field_list_type = self._read_type_key(reader)
        flags = reader.u16()
        reader.u32()  # containing type
        reader.u32()  # derivation list
        reader.u32()  # vtable shape
        name = self.name(reader.u32())
        result = {
            "type": TYPE_NAMES[leaf],
            "field_list_type": field_list_type,
            "name": normalize_delphi_name(name),
            "size": self._read_numeric(reader),
        }
        if flags & 0x80 or field_list_type == 0:
            result["is_forward_ref"] = True
        return result

    def _read_pascal_array_type(self, reader: BinaryReader, leaf: int) -> dict:
        element_type = self._normalize_pascal_array_element_type(
            self._read_type_key(reader)
        )
        reader.u32()  # index/base type
        name = normalize_delphi_name(self.name(reader.u32()))
        if leaf == TYPE_PAS_SET:
            reader.offset = reader.end
            size = 32
        else:
            size = self._read_numeric(reader)
            reader.offset = reader.end

        return {
            "type": "LF_ARRAY",
            "array_type": element_type,
            "name": name,
            "size": size,
        }

    def _read_field_list(self, reader: BinaryReader) -> dict:
        result: dict = {"type": "LF_FIELDLIST"}
        members: list[FieldListItem] = []
        variants: list[EnumItem] = []

        while reader.remaining() >= 2:
            leaf = reader.u16()

            if leaf == TYPE_LF_BCLASS:
                superclass = self._read_type_key(reader)
                reader.u16()  # attributes
                superclasses = result.setdefault("super", {})
                superclasses[superclass] = self._read_numeric(reader)

            elif leaf in (TYPE_LF_VBCLASS, TYPE_LF_IVBCLASS):
                virtual_base_pointer = result.setdefault(
                    "vbase", VirtualBasePointer(vboffset=-1, bases=[])
                )
                base_type = self._read_type_key(reader)
                reader.u32()  # virtual base pointer type
                reader.u16()  # attributes
                vboffset = self._read_numeric(reader)
                vbindex = self._read_numeric(reader)
                if virtual_base_pointer.vboffset == -1:
                    virtual_base_pointer.vboffset = vboffset
                virtual_base_pointer.bases.append(
                    VirtualBaseClass(
                        type=base_type,
                        index=vbindex,
                        direct=leaf == TYPE_LF_VBCLASS,
                    )
                )
                virtual_base_pointer.bases.sort(key=lambda base: base.index)

            elif leaf == TYPE_LF_ENUMERATE:
                reader.i16()  # attributes
                name = normalize_delphi_name(self.name(reader.u32()))
                reader.u32()  # browser offset
                value = self._read_numeric(reader)
                variants.append(EnumItem(name=name or "", value=value))

            elif leaf == TYPE_LF_INDEX:
                reader.u32()  # continuation field list

            elif leaf == TYPE_LF_MEMBER:
                member_type = self._read_type_key(reader)
                reader.u16()  # attributes
                name = normalize_delphi_name(self.name(reader.u32()))
                reader.u32()  # browser offset
                members.append(
                    FieldListItem(
                        offset=self._read_numeric(reader),
                        name=name or "",
                        type=member_type,
                    )
                )

            elif leaf == TYPE_LF_STMEMBER:
                reader.u32()  # type
                reader.u16()  # attributes
                reader.u32()  # name
                reader.u32()  # browser offset

            elif leaf == TYPE_LF_METHOD:
                reader.u16()  # method count
                reader.u32()  # method list type
                reader.u32()  # name

            elif leaf == TYPE_LF_NESTTYPE:
                reader.u32()  # nested type
                reader.u32()  # name
                reader.u32()  # browser offset

            elif leaf == TYPE_LF_VFUNCTAB:
                reader.u32()  # vtable shape pointer
                offset = self._read_numeric(reader)
                members.append(
                    FieldListItem(
                        offset=offset,
                        name="vftable",
                        type=CVInfoTypeEnum.T_32PVOID,
                    )
                )

            else:
                self._log_unhandled_type(leaf)
                break

            self._skip_padding(reader)

        if members:
            result["members"] = members
        if variants:
            result["variants"] = variants

        return result

    def _read_global_symbols(self, data: bytes):
        if len(data) < 32:
            self._read_symbols(data, has_signature=False)
            return

        reader = BinaryReader(data)
        reader.u16()  # symbol hash
        reader.u16()  # address hash
        symbol_size = reader.u32()
        reader.u32()  # symbol hash bytes
        reader.u32()  # address hash bytes
        reader.u32()  # udt count
        reader.u32()  # other count
        reader.u32()  # total count
        reader.u32()  # namespace count
        symbol_start = reader.offset
        symbol_end = min(symbol_start + symbol_size, len(data))
        self._read_symbols(data[symbol_start:symbol_end], has_signature=False)

    def _read_symbols(self, data: bytes, *, has_signature: bool):
        offset = 4 if has_signature and len(data) >= 4 else 0
        end = len(data)
        self._current_function = None
        self._block_level = 0

        while offset + 4 <= end:
            size = struct.unpack_from("<H", data, offset)[0]
            if size < 2:
                break

            record_start = offset + 2
            record_end = record_start + size
            if record_end > end:
                break

            symbol_type = struct.unpack_from("<H", data, record_start)[0]
            payload = data[record_start + 2 : record_end]
            self._parse_symbol_record(symbol_type, payload)
            offset = record_end

    def _parse_symbol_record(self, symbol_type: int, payload: bytes):
        reader = BinaryReader(payload)

        try:
            if symbol_type in (SYMBOL_TYPE_LPROC32, SYMBOL_TYPE_GPROC32):
                self._read_proc_symbol(symbol_type, reader)
            elif symbol_type == SYMBOL_TYPE_BPREL32:
                self._read_bprel_symbol(reader)
            elif symbol_type == SYMBOL_TYPE_REGISTER:
                self._read_register_symbol(reader)
            elif symbol_type in (SYMBOL_TYPE_LDATA32, SYMBOL_TYPE_GDATA32):
                self._read_data_symbol(symbol_type, reader)
            elif symbol_type == SYMBOL_TYPE_PUB32:
                self._read_public_symbol(reader)
            elif symbol_type in (SYMBOL_TYPE_GPROCREF, SYMBOL_TYPE_GDATAREF):
                self._read_global_ref(symbol_type, reader)
            elif symbol_type == SYMBOL_TYPE_VFTPATH32:
                self._read_vftpath_symbol(reader)
            elif symbol_type == SYMBOL_TYPE_BLOCK32:
                self._block_level += 1
            elif symbol_type == SYMBOL_TYPE_END:
                if self._block_level > 0:
                    self._block_level -= 1
                else:
                    self._current_function = None
            elif symbol_type in SYMBOL_TYPES_IGNORED:
                pass
            else:
                self._log_unhandled_symbol(symbol_type)
        except DelphiTd32Error:
            logger.debug("Failed to parse TD32 symbol 0x%04x", symbol_type)

    def _read_proc_symbol(self, symbol_type: int, reader: BinaryReader):
        reader.u32()  # parent
        reader.u32()  # end
        reader.u32()  # next
        size = reader.u32()
        reader.u32()  # debug start
        reader.u32()  # debug end
        offset = reader.u32()
        section = reader.u16()

        if reader.remaining() >= 14:
            reader.u16()  # flags / near-far
            func_type = self._read_type_key(reader)
            name = normalize_delphi_name(self.name(reader.u32()))
        elif reader.remaining() >= 10:
            func_type = self._read_type_key(reader)
            reader.u16()  # near-far / reserved
            name = normalize_delphi_name(self.name(reader.u32()))
        else:
            func_type = CVInfoTypeEnum.T_NOTYPE
            name = None

        self._current_function = SymbolsEntry(
            type="S_GPROC32" if symbol_type == SYMBOL_TYPE_GPROC32 else "S_LPROC32",
            section=section,
            offset=offset,
            size=size,
            func_type=func_type,
            name=name or "",
            frame_pointer_present=True,
        )
        self.symbols.append(self._current_function)

    def _read_bprel_symbol(self, reader: BinaryReader):
        stack_offset = reader.i32()
        data_type = self._read_type_key(reader)
        name = normalize_delphi_name(self.name(reader.u32()))

        if self._current_function is None:
            return

        self._current_function.symbols.append(
            StackOrRegisterSymbol(
                symbol_type="S_BPREL32",
                location=f"[{stack_offset & 0xFFFFFFFF:08X}]",
                data_type=data_type,
                name=name or "",
            )
        )

    def _read_register_symbol(self, reader: BinaryReader):
        data_type = self._read_type_key(reader)
        register = REGISTER_NAMES.get(reader.u16())
        name = normalize_delphi_name(self.name(reader.u32()))

        if self._current_function is None or register is None:
            return

        self._current_function.symbols.append(
            StackOrRegisterSymbol(
                symbol_type="S_REGISTER",
                location=register,
                data_type=data_type,
                name=name or "",
            )
        )

    def _read_data_symbol(self, symbol_type: int, reader: BinaryReader):
        offset = reader.u32()
        section = reader.u16()
        reader.u16()  # flags
        data_type = self._read_type_key(reader)
        name = normalize_delphi_name(self.name(reader.u32()))

        if symbol_type == SYMBOL_TYPE_LDATA32 and self._current_function is not None:
            self._current_function.static_variables.append(
                LdataEntry(
                    section=section, offset=offset, type=data_type, name=name or ""
                )
            )
            return

        self.globals.append(
            GdataEntry(
                section=section,
                offset=offset,
                type=data_type,
                name=name or "",
                is_global=symbol_type == SYMBOL_TYPE_GDATA32,
            )
        )
        if symbol_type == SYMBOL_TYPE_GDATA32:
            self._add_public(section, offset, 0, name)

    def _read_public_symbol(self, reader: BinaryReader):
        offset = reader.u32()
        section = reader.u16()
        flags = reader.u16()
        reader.u32()  # type index
        name = self.name(reader.u32())
        self._add_public(section, offset, flags, name)

    def _read_global_ref(self, symbol_type: int, reader: BinaryReader):
        reader.u32()  # unknown
        data_type = self._read_type_key(reader)
        name = normalize_delphi_name(self.name(reader.u32()))
        reader.u32()  # unknown
        offset = reader.u32()
        section = reader.u16()

        if symbol_type == SYMBOL_TYPE_GDATAREF:
            self.globals.append(
                GdataEntry(
                    section=section,
                    offset=offset,
                    type=data_type,
                    name=name or "",
                    is_global=True,
                )
            )
        else:
            self._add_public(section, offset, 0, name)

    def _read_vftpath_symbol(self, reader: BinaryReader):
        offset = reader.u32()
        section = reader.u16()
        reader.u16()  # reserved
        self.vtables.append(
            Td32Vtable(
                section=section,
                offset=offset,
                root_type=self._read_type_key(reader),
                path_type=self._read_type_key(reader),
            )
        )

    def _add_public(self, section: int, offset: int, flags: int, name: str | None):
        if name is None:
            return

        key = (section, offset, name)
        if key in self._seen_publics:
            return

        self._seen_publics.add(key)
        self.publics.append(
            PublicsEntry(
                type="S_PUB32",
                section=section,
                offset=offset,
                flags=flags,
                name=name,
            )
        )

    def _read_source_module(self, data: bytes):
        if len(data) < 4:
            return

        reader = BinaryReader(data)
        file_count = reader.u16()
        segment_count = reader.u16()
        file_offsets = [reader.u32() for _ in range(file_count)]

        # Module-level segment ranges and segment indexes are useful for lookup
        # scanners, but each source-file line table carries the segment index we
        # need for reccmp line matching.
        reader.skip(segment_count * 8)
        reader.skip(segment_count * 2)
        if segment_count % 2:
            reader.skip(2)

        for file_offset in file_offsets:
            if file_offset >= len(data):
                continue
            self._read_source_file(data, file_offset)

    def _read_source_file(self, data: bytes, file_offset: int):
        reader = BinaryReader(data, file_offset)
        segment_count = reader.u16()
        filename = self.name(reader.u32())
        line_offsets = [reader.u32() for _ in range(segment_count)]
        reader.skip(segment_count * 8)

        if filename is None:
            return

        path = PureWindowsPath(filename)
        for line_offset in line_offsets:
            if line_offset >= len(data):
                continue

            line_reader = BinaryReader(data, line_offset)
            section = line_reader.u16()
            pair_count = line_reader.u16()
            offsets = [line_reader.u32() for _ in range(pair_count)]
            line_numbers = [line_reader.u16() for _ in range(pair_count)]

            self.lines.setdefault(path, []).extend(
                LineValue(
                    line_number=line_number,
                    section=section,
                    offset=offset,
                )
                for offset, line_number in zip(offsets, line_numbers)
            )

    def _read_type_key(self, reader: BinaryReader) -> CvdumpTypeKey:
        return CvdumpTypeKey(reader.u32())

    def _is_type_key_resolvable(self, type_key: CvdumpTypeKey) -> bool:
        if type_key.is_scalar():
            return type_key in CvdumpTypeMap

        return type_key in self.types.keys

    def _normalize_pascal_array_element_type(
        self, type_key: CvdumpTypeKey
    ) -> CvdumpTypeKey:
        if type_key == CVInfoTypeEnum.T_PASCHAR:
            return CVInfoTypeEnum.T_RCHAR

        return type_key

    def _read_call_type(self, value: int) -> Td32CallConvention:
        return decode_td32_call_convention(value)

    def _read_numeric(self, reader: BinaryReader) -> int:
        value = reader.u16()
        if value < 0x8000:
            return value

        if value == 0x8000:
            return reader.i8()
        if value == 0x8001:
            return reader.i16()
        if value == 0x8002:
            return reader.u16()
        if value == 0x8003:
            return reader.i32()
        if value == 0x8004:
            return reader.u32()

        raise DelphiTd32Error(f"Unsupported TD32 numeric leaf 0x{value:04x}")

    def _skip_padding(self, reader: BinaryReader):
        if reader.remaining() <= 0:
            return

        padding = reader.u8()
        if padding > 0xF0:
            reader.skip((padding & 0x0F) - 1)
        else:
            reader.seek(reader.offset - 1)

    def _opaque_byte_array(self, name: str | None, size: int) -> dict:
        return {
            "type": "LF_ARRAY",
            "array_type": CVInfoTypeEnum.T_UCHAR,
            "name": name,
            "size": size,
        }

    def _log_unhandled_subsection(self, subsection_type: int):
        if subsection_type not in self.unhandled_subsections:
            self.unhandled_subsections.add(subsection_type)
            logger.info("Unhandled TD32 subsection type: 0x%04x", subsection_type)

    def _log_unhandled_symbol(self, symbol_type: int):
        if symbol_type not in self.unhandled_symbols:
            self.unhandled_symbols.add(symbol_type)
            logger.info("Unhandled TD32 symbol type: 0x%04x", symbol_type)

    def _log_unhandled_type(self, leaf: int):
        if leaf not in self.unhandled_types:
            self.unhandled_types.add(leaf)
            logger.info("Unhandled TD32 type leaf: 0x%04x", leaf)


class DelphiTd32Analysis(CvdumpAnalysis):
    """CvdumpAnalysis-compatible view of embedded Delphi TD32 debug info."""

    def __init__(self, parser: DelphiTd32Parser, image: PEImage | None = None):
        self._image = image
        super().__init__(parser)  # type: ignore[arg-type]
        self._apply_delphi_vtables()

    @classmethod
    def from_bytes(cls, data: bytes) -> "DelphiTd32Analysis":
        return cls(DelphiTd32Parser.from_bytes(data))

    @classmethod
    def from_file(cls, path: Path) -> "DelphiTd32Analysis":
        data = path.read_bytes()
        image: PEImage | None = None
        try:
            detected_image = detect_image(path)
            if isinstance(detected_image, PEImage):
                image = detected_image
        except (OSError, ValueError, struct.error):
            pass

        try:
            return cls(DelphiTd32Parser.from_bytes(data), image=image)
        except DelphiTd32Error:
            if not isinstance(image, PEImage):
                raise

            return cls(
                DelphiTd32Parser.from_bytes(extract_td32_stream_from_pe(image)),
                image=image,
            )

    @classmethod
    def from_pe(cls, image: PEImage) -> "DelphiTd32Analysis":
        return cls(
            DelphiTd32Parser.from_bytes(extract_td32_stream_from_pe(image)),
            image=image,
        )

    def _apply_delphi_vtables(self):
        parser = cast(DelphiTd32Parser, self.parser)
        node_by_key = {(node.section, node.offset): node for node in self.nodes}

        for node in self.nodes:
            class_name = delphi_vmt_class_name(node.name())
            if class_name is not None:
                node.node_type = EntityType.VTABLE
                node.friendly_name = class_name

        for vtable in parser.vtables:
            key = (vtable.section, vtable.offset)
            vtable_node = node_by_key.get(key)
            if vtable_node is None:
                vtable_node = CvdumpNode(section=vtable.section, offset=vtable.offset)
                node_by_key[key] = vtable_node

            root_name = parser.type_name(vtable.root_type)
            vtable_node.node_type = EntityType.VTABLE
            vtable_node.friendly_name = root_name or vtable_node.friendly_name

        self._apply_discovered_delphi_vmts(parser, node_by_key)
        self.nodes = [node for _, node in sorted(node_by_key.items())]
        self._estimate_size()

    def _apply_discovered_delphi_vmts(
        self,
        parser: DelphiTd32Parser,
        node_by_key: dict[tuple[int, int], CvdumpNode],
    ):
        if self._image is None:
            return

        class_infos = self._delphi_class_infos_by_short_name(parser)
        if not class_infos:
            return

        code_ranges = [region.range for region in self._image.get_code_regions()]
        ignored_sections = {".debug", ".idata", ".reloc", ".rsrc"}
        for section_index, section in enumerate(self._image.sections, start=1):
            if section.name.lower() in ignored_sections:
                continue

            data = bytes(section.view)
            if len(data) < 44:
                continue

            for offset in range(40, len(data) - 3, 4):
                class_name_ptr = int.from_bytes(
                    data[offset - 40 : offset - 36], "little"
                )
                class_name = self._read_pascal_short_string(class_name_ptr)
                if class_name is None:
                    continue

                matching_infos = class_infos.get(class_name.lower())
                if matching_infos is None:
                    continue

                instance_size = int.from_bytes(
                    data[offset - 36 : offset - 32], "little"
                )
                full_name = self._matching_delphi_class_name(
                    matching_infos, instance_size
                )
                if full_name is None:
                    continue

                vmt_addr = section.virtual_address + offset
                slot_count = self._count_delphi_vmt_slots(vmt_addr, code_ranges)
                if slot_count == 0:
                    continue

                key = (section_index, offset)
                node = node_by_key.get(key)
                if node is None:
                    node = CvdumpNode(section=section_index, offset=offset)
                    node_by_key[key] = node

                node.node_type = EntityType.VTABLE
                node.friendly_name = full_name
                node.confirmed_size = slot_count * 4

    def _delphi_class_infos_by_short_name(
        self, parser: DelphiTd32Parser
    ) -> dict[str, list[tuple[str, int | None]]]:
        result: dict[str, list[tuple[str, int | None]]] = {}

        for type_key, type_obj in parser.types.keys.items():
            if type_obj.get("type") != "LF_CLASS":
                continue

            name = type_obj.get("name")
            if not isinstance(name, str) or not name:
                continue

            field_list_type = type_obj.get("field_list_type")
            if not isinstance(field_list_type, CvdumpTypeKey):
                continue

            field_list = parser.types.keys.get(field_list_type)
            if field_list is None:
                continue

            members = field_list.get("members", [])
            has_vftable = any(
                member.name == "vftable" and member.offset == 0 for member in members
            )
            if not has_vftable:
                continue

            try:
                instance_size = parser.types.get(type_key).size
            except (CvdumpKeyError, CvdumpIntegrityError):
                instance_size = type_obj.get("size")

            short_name = name.rsplit(".", 1)[-1]
            result.setdefault(short_name.lower(), []).append((name, instance_size))

        return result

    def _matching_delphi_class_name(
        self, class_infos: list[tuple[str, int | None]], instance_size: int
    ) -> str | None:
        for full_name, expected_size in class_infos:
            if expected_size in (None, instance_size):
                return full_name

        return None

    def _read_pascal_short_string(self, addr: int) -> str | None:
        if self._image is None:
            return None

        try:
            raw_length = self._image.read(addr, 1)[0]
            if raw_length == 0 or raw_length > 80:
                return None

            raw_text = self._image.read(addr + 1, raw_length)
            text = raw_text.decode("latin1")
        except (
            InvalidVirtualAddressError,
            InvalidVirtualReadError,
            UnicodeDecodeError,
        ):
            return None

        if any(ord(char) < 32 or ord(char) > 126 for char in text):
            return None

        return text

    def _count_delphi_vmt_slots(self, addr: int, code_ranges: list[range]) -> int:
        if self._image is None:
            return 0

        slot_count = 0
        while slot_count < 512:
            try:
                target = int.from_bytes(
                    self._image.read(addr + slot_count * 4, 4), "little"
                )
            except (InvalidVirtualAddressError, InvalidVirtualReadError):
                break

            if not any(target in code_range for code_range in code_ranges):
                break

            slot_count += 1

        return slot_count
