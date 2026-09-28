"""Anonymous literal bytes participate in normalized function comparisons."""

import struct
from typing import cast
from unittest.mock import Mock, patch

import pytest

from reccmp.compare.asm.literals import literal_read
from reccmp.compare.asm.parse import ParseAsm
from reccmp.compare.asm.types import DisasmLiteInst
from reccmp.compare.db import EntityDb, ReccmpMatch
from reccmp.compare.functions import FunctionComparator
from reccmp.compare.lines import LinesDb
from reccmp.compare.literals import create_literal_lookup
from reccmp.formats import PEImage
from reccmp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.formats.image import ImageSection, ImageSectionFlags
from reccmp.types import EntityType, ImageId

from .raw_image import RawImage


def pe_image(data: bytes) -> PEImage:
    """Use real bounded reads, with explicit PE permissions/relocation evidence."""
    raw = RawImage.from_memory(data)
    image = Mock(spec=PEImage)
    image.read = raw.read
    image.imagebase = 0
    image.is_valid_vaddr = raw.is_valid_vaddr
    image.is_relocated_addr = lambda _addr: False
    image.is_debug = False
    image.relocations = set()
    image.sections = (
        ImageSection(
            virtual_range=range(len(data)),
            physical_range=range(len(data)),
            view=raw.view,
            flags=ImageSectionFlags.READ | ImageSectionFlags.EXECUTE,
        ),
    )
    return cast(PEImage, image)


@pytest.mark.parametrize(
    "mnemonic, operands, expected",
    [
        ("mov", "al, byte ptr [0x1234]", (0x1234, 1)),
        ("mov", "ax, word ptr [0x1234]", (0x1234, 2)),
        ("mov", "eax, dword ptr [0x1234]", (0x1234, 4)),
        ("movzx", "eax, byte ptr [0x1234]", (0x1234, 1)),
        ("movsx", "eax, word ptr [0x1234]", (0x1234, 2)),
        ("fld", "qword ptr [0x1234]", (0x1234, 8)),
        ("fld", "xword ptr [0x1234]", (0x1234, 10)),
        ("fild", "dword ptr [0x1234]", (0x1234, 4)),
        ("mov", "byte ptr [0x1234], al", None),
        ("add", "byte ptr [0x1234], 1", None),
        ("lea", "eax, [0x1234]", None),
        ("mov", "eax, 0x1234", None),
        ("mov", "al, byte ptr fs:[0x1234]", None),
        ("mov", "al, byte ptr [eax + 0x1234]", None),
        ("mov", "eax, dword ptr [eax*4 + 0x1234]", None),
        ("call", "dword ptr [0x1234]", None),
        ("jmp", "dword ptr [0x1234]", None),
        ("prefetchnta", "byte ptr [0x1234]", None),
    ],
)
def test_literal_read(mnemonic, operands, expected):
    assert literal_read(DisasmLiteInst(0x1000, 6, mnemonic, operands)) == expected


def test_literals_preserve_address_identity_and_read_width():
    parser = ParseAsm(
        literal_lookup=lambda addr, size, owning_function=None: b"\x0e\x09"[:size]
    )
    instructions = [
        ("al, byte ptr [0x1234]", "al, byte ptr [<OFFSET1>] ; literal bytes: 0e"),
        ("ax, word ptr [0x1234]", "ax, word ptr [<OFFSET1>] ; literal bytes: 0e 09"),
        ("al, byte ptr [0x1235]", "al, byte ptr [<OFFSET2>] ; literal bytes: 0e"),
        ("al, byte ptr [0x1234]", "al, byte ptr [<OFFSET1>] ; literal bytes: 0e"),
    ]
    for operand, expected in instructions:
        assert parser.sanitize(DisasmLiteInst(0, 6, "mov", operand)) == (
            "mov",
            expected,
        )
    assert parser.replacements == {0x1234: "<OFFSET1>", 0x1235: "<OFFSET2>"}
    parser.reset()
    assert parser.sanitize(DisasmLiteInst(0, 6, "mov", "al, byte ptr [0x1235]")) == (
        "mov",
        instructions[0][1],
    )


def test_named_operand_keeps_symbol_comparison():
    lookup = Mock(return_value=b"\x0e")
    parser = ParseAsm(name_lookup=lambda *_a, **_kw: "NamedData", literal_lookup=lookup)
    assert parser.sanitize(DisasmLiteInst(0, 5, "mov", "al, byte ptr [0x1234]")) == (
        "mov",
        "al, byte ptr [NamedData]",
    )
    lookup.assert_not_called()


def test_active_code_is_not_a_literal():
    lookup = Mock(return_value=b"\xa0")
    parser = ParseAsm(literal_lookup=lookup)
    parser.parse_asm(b"\xa0\x00\x10\x00\x00", 0x1000)
    lookup.assert_not_called()


@pytest.mark.parametrize("relocation", [0x0D, 0x0E, 0x0F, 0x10, 0x11])
def test_relocated_storage_is_not_a_scalar(relocation: int):
    image = pe_image(bytes(0x20))
    image.relocations.add(relocation)
    lookup = create_literal_lookup(EntityDb(), ImageId.ORIG, image)
    assert lookup is not None
    assert lookup(0x10, 2) is None


@pytest.mark.parametrize("relocation", [0x0C, 0x12])
def test_adjacent_relocations_do_not_exclude_literal(relocation: int):
    image = pe_image(bytes(0x20))
    image.relocations.add(relocation)
    lookup = create_literal_lookup(EntityDb(), ImageId.ORIG, image)
    assert lookup is not None
    assert lookup(0x10, 2) == b"\x00\x00"


@pytest.mark.parametrize(
    "flags",
    [
        ImageSectionFlags.READ | ImageSectionFlags.WRITE,
        ImageSectionFlags.READ | ImageSectionFlags.BSS,
        ImageSectionFlags.EXECUTE,
    ],
)
def test_unproven_storage_is_not_a_literal(flags: ImageSectionFlags):
    image = pe_image(bytes(0x20))
    image.sections = (
        ImageSection(
            virtual_range=range(0x20),
            physical_range=range(0x20),
            view=memoryview(bytes(0x20)),
            flags=flags,
        ),
    )
    lookup = create_literal_lookup(EntityDb(), ImageId.ORIG, image)
    assert lookup is not None
    assert lookup(0x10, 1) is None


def test_literal_requires_complete_physical_and_virtual_range():
    image = pe_image(bytes(0x10))
    image.sections = (
        ImageSection(
            virtual_range=range(0x20),
            physical_range=range(0x10),
            view=memoryview(bytes(0x10)),
            flags=ImageSectionFlags.READ,
        ),
    )
    lookup = create_literal_lookup(EntityDb(), ImageId.ORIG, image)
    assert lookup is not None
    assert lookup(0x10, 1) is None  # Virtual zero-fill is not a literal.
    assert lookup(0x0F, 2) is None
    assert lookup(0x20, 1) is None
    assert lookup(0x0F, 1) == b"\x00"
    assert lookup(0, 0) is None


@pytest.mark.parametrize("entity_type", [EntityType.FUNCTION, EntityType.DATA])
@pytest.mark.parametrize("address", [0x0F, 0x10, 0x11])
def test_known_storage_is_not_anonymous(entity_type: EntityType, address: int):
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, address, type=entity_type, size=2)
    lookup = create_literal_lookup(db, ImageId.ORIG, pe_image(bytes(0x20)))
    assert lookup is not None
    assert lookup(0x10, 2) is None


def test_procedure_gap_can_contain_literal_pool():
    db = EntityDb()
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            0,
            type=EntityType.FUNCTION,
            size=0x10,
            max_size=0x20,
        )
    lookup = create_literal_lookup(db, ImageId.ORIG, pe_image(bytes(0x20)))
    assert lookup is not None
    assert lookup(0x10, 1) == b"\x00"


def test_nested_label_does_not_hide_enclosing_code_range():
    db = EntityDb()
    # FunctionComparator creates the lookup before symbols are ingested.
    lookup = create_literal_lookup(db, ImageId.ORIG, pe_image(bytes(0x20)))
    assert lookup is not None
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0, type=EntityType.FUNCTION, size=0x18)
        batch.set(ImageId.ORIG, 0x10, type=EntityType.LABEL)
    assert lookup(0x11, 1) is None
    assert lookup(0x18, 1) == b"\x00"


@pytest.mark.parametrize("changed", [False, True])
def test_debug_function_size_can_include_literal_pool(changed: bool):
    """TCanvas.LineTo: one symbol size includes alignment and an unnamed set."""
    code = b"\x8a\x15\x10\x00\x00\x00\xc3"
    original = code.ljust(0x10, b"\xcc") + b"\x0d"
    rebuilt = original[:-1] + (b"\x09" if changed else b"\x0d")
    db = EntityDb()
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 0, type=EntityType.FUNCTION, size=len(code))
        batch.set(ImageId.RECOMP, 0, type=EntityType.FUNCTION, size=len(rebuilt))
        batch.match(0, 0)
    match = db.get(ImageId.ORIG, 0)
    assert isinstance(match, ReccmpMatch)
    comparator = FunctionComparator(
        db, LinesDb(), pe_image(original), pe_image(rebuilt), Mock()
    )
    result = comparator.compare_function(match)
    assert (result.match_ratio < 1.0) == changed
    assert not result.is_effective_match
    assert result.diff.orig_inst[0][1].endswith("; literal bytes: 0d")
    assert "; literal bytes:" in result.diff.recomp_inst[0][1]


@pytest.mark.parametrize("error", [InvalidVirtualAddressError, InvalidVirtualReadError])
def test_failed_literal_read_is_safe(error):
    image = pe_image(bytes(0x20))
    lookup = create_literal_lookup(EntityDb(), ImageId.ORIG, image)
    assert lookup is not None
    with patch.object(image, "read", side_effect=error):
        assert lookup(0x10, 1) is None


def test_other_formats_need_relocation_evidence():
    assert (
        create_literal_lookup(EntityDb(), ImageId.ORIG, RawImage.from_memory()) is None
    )


@pytest.mark.parametrize(
    "load, value",
    [
        (b"\x66\xa1", b"\x01\x02"),  # mov ax, word ptr [addr]
        (b"\xa1", b"\x01\x02\x03\x04"),  # mov eax, dword ptr [addr]
        (b"\xdd\x05", bytes.fromhex("000000000000f03f")),  # fld qword ptr [addr]
        (b"\xdb\x2d", bytes.fromhex("0000000000000080ff3f")),  # fld xword ptr [addr]
    ],
)
def test_entire_load_width_is_compared(load: bytes, value: bytes):
    code = load + struct.pack("<I", 0x10) + b"\xc3"
    memory = code.ljust(0x10, b"\x00") + value
    changed = memory[:-1] + bytes([memory[-1] ^ 1])
    comparator = FunctionComparator(
        EntityDb(), LinesDb(), pe_image(memory), pe_image(changed), Mock()
    )
    result = comparator.compare_function(
        ReccmpMatch(0, 0, {"type": EntityType.FUNCTION, "recomp_size": len(code)})
    )
    assert result.match_ratio < 1.0
    assert not result.is_effective_match
    assert result.diff.orig_inst[0][1].endswith(f"; literal bytes: {value.hex(' ')}")


def test_equal_values_do_not_hide_a_changed_reference_pattern():
    first = b"\xa0\x20\x00\x00\x00"
    second = b"\xa0\x21\x00\x00\x00"
    orig = (first + first + b"\xc3").ljust(0x20, b"\x00") + b"\x0e\x0e"
    recomp = (first + second + b"\xc3").ljust(0x20, b"\x00") + b"\x0e\x0e"
    comparator = FunctionComparator(
        EntityDb(), LinesDb(), pe_image(orig), pe_image(recomp), Mock()
    )
    result = comparator.compare_function(
        ReccmpMatch(0, 0, {"type": EntityType.FUNCTION, "recomp_size": 11})
    )
    assert result.match_ratio < 1.0
    assert not result.is_effective_match
    assert "<OFFSET1>" in result.diff.orig_inst[1][1]
    assert "<OFFSET2>" in result.diff.recomp_inst[1][1]


@pytest.mark.parametrize("rebuilt_value, matches", [(0x0E, True), (0x09, False)])
@pytest.mark.parametrize("load", [b"\xa0", b"\x8a\x15", b"\x0f\xb6\x05"])
def test_moved_delphi_set_literals_are_compared_by_value(rebuilt_value, matches, load):
    """Both the procedure and its trailing pool move; only the value matters."""
    images = []
    for start, value in ((0x100, 0x0E), (0x200, rebuilt_value)):
        memory = bytearray(0x300)
        literal_addr = start + 0x10
        code = load + struct.pack("<I", literal_addr) + b"\xc3"
        memory[start : start + len(code)] = code
        memory[literal_addr] = value
        # Adjacent padding is deliberately different and is not read by MOV.
        memory[literal_addr + 1] = start // 0x100
        image = pe_image(bytes(memory))
        image.relocations.add(start + len(load))
        images.append(image)

    comparator = FunctionComparator(EntityDb(), LinesDb(), images[0], images[1], Mock())
    result = comparator.compare_function(
        ReccmpMatch(
            0x100,
            0x200,
            {"type": EntityType.FUNCTION, "recomp_size": len(load) + 5},
        )
    )
    assert (result.match_ratio == 1.0) == matches
    assert not result.is_effective_match
    assert result.diff.orig_inst[0][1].endswith("; literal bytes: 0e")
    assert result.diff.recomp_inst[0][1].endswith(
        f"; literal bytes: {rebuilt_value:02x}"
    )
