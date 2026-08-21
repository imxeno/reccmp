"""Tests for matching Delphi names and VMTs across analysis sources."""

import struct
from unittest.mock import Mock

import pytest

from reccmp.compare.db import EntityDb
from reccmp.compare.event import ReccmpEvent, ReccmpReportProtocol
from reccmp.compare.match_delphi import (
    match_delphi_library_layout,
    match_delphi_library_functions,
    match_delphi_lifecycle_guards,
)
from reccmp.compare.match_msvc import (
    match_delphi_idr_placeholders,
    match_functions,
    match_vtables,
)
from reccmp.formats.image import ImageSection, ImageSectionFlags
from reccmp.types import EntityType, ImageId

from .raw_image import RawImage


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def _lifecycle_image(
    initialization_guard: int,
    finalization_guards: tuple[int, ...],
    *,
    initialization_uses_dec: bool = False,
    data_flags: ImageSectionFlags = (ImageSectionFlags.READ | ImageSectionFlags.WRITE),
) -> tuple[RawImage, int, int]:
    initialization_address = 0x10
    finalization_address = 0x40
    memory = bytearray(0x200)

    if initialization_uses_dec:
        initialization = b"\xff\x0d" + struct.pack("<I", initialization_guard) + b"\xc3"
    else:
        initialization = b"\x83\x2d" + struct.pack("<I", initialization_guard) + b"\x01\xc3"
    finalization = b"".join(b"\xff\x05" + struct.pack("<I", guard) for guard in finalization_guards) + b"\xc3"
    memory[initialization_address : initialization_address + len(initialization)] = initialization
    memory[finalization_address : finalization_address + len(finalization)] = finalization

    image = RawImage.from_memory(bytes(memory))
    image.sections = (
        ImageSection(
            virtual_range=range(0, 0x100),
            physical_range=range(0, 0x100),
            view=image.view[:0x100],
            name=".text",
            flags=ImageSectionFlags.READ | ImageSectionFlags.EXECUTE,
        ),
        ImageSection(
            virtual_range=range(0x100, 0x200),
            physical_range=range(0x100, 0x200),
            view=image.view[0x100:0x200],
            name=".data",
            flags=data_flags,
        ),
    )
    return image, len(initialization), len(finalization)


def _add_lifecycle_pair(
    db: EntityDb,
    initialization_size: int,
    finalization_size: int,
    *,
    owner_unit: str = "Unit1",
):
    with db.batch() as batch:
        for image_id in (ImageId.ORIG, ImageId.RECOMP):
            delphi_attributes = {"owner_unit": owner_unit, "is_delphi": True} if image_id == ImageId.RECOMP else {}
            batch.set(
                image_id,
                0x10,
                name=f"{owner_unit}.Initialization",
                type=EntityType.FUNCTION,
                size=initialization_size,
                **delphi_attributes,
            )
            batch.set(
                image_id,
                0x40,
                name=f"{owner_unit}.Finalization",
                type=EntityType.FUNCTION,
                size=finalization_size,
                **delphi_attributes,
            )
        batch.match(0x10, 0x10)
        batch.match(0x40, 0x40)


@pytest.mark.parametrize("initialization_uses_dec", [False, True])
def test_match_delphi_lifecycle_guard_from_generated_code(db: EntityDb, initialization_uses_dec: bool):
    original_image, initialization_size, finalization_size = _lifecycle_image(
        0x120, (0x120,), initialization_uses_dec=initialization_uses_dec
    )
    recompiled_image, _, _ = _lifecycle_image(0x140, (0x140,), initialization_uses_dec=initialization_uses_dec)
    _add_lifecycle_pair(db, initialization_size, finalization_size)
    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            0x140,
            name="$BuildSpecificName",
            owner_unit="Unit1",
            type=EntityType.DATA,
            is_delphi=True,
        )

    match_delphi_lifecycle_guards(db, original_image, recompiled_image)

    guard = db.get(ImageId.ORIG, 0x120)
    assert guard is not None
    assert guard.recomp_addr == 0x140
    assert guard.get("name") == "$BuildSpecificName"
    assert guard.best_name() == "Unit1.UnitFinalizationGuard"
    assert guard.get("compiler_generated") is True
    assert guard.any_size(ImageId.ORIG) == 4
    assert guard.any_size(ImageId.RECOMP) == 4


@pytest.mark.parametrize(
    ("initialization_guard", "finalization_guards", "data_flags"),
    [
        (
            0x120,
            (0x124,),
            ImageSectionFlags.READ | ImageSectionFlags.WRITE,
        ),
        (
            0x120,
            (0x120, 0x124),
            ImageSectionFlags.READ | ImageSectionFlags.WRITE,
        ),
        (0x120, (0x120,), ImageSectionFlags.READ),
        (
            0x120,
            (0x120,),
            ImageSectionFlags.READ | ImageSectionFlags.EXECUTE,
        ),
    ],
)
def test_match_delphi_lifecycle_guard_rejects_unsafe_inference(
    db: EntityDb,
    initialization_guard: int,
    finalization_guards: tuple[int, ...],
    data_flags: ImageSectionFlags,
):
    original_image, initialization_size, finalization_size = _lifecycle_image(
        initialization_guard,
        finalization_guards,
        data_flags=data_flags,
    )
    recompiled_image, _, _ = _lifecycle_image(0x140, (0x140,))
    _add_lifecycle_pair(db, initialization_size, finalization_size)
    report = Mock(spec=ReccmpReportProtocol)

    match_delphi_lifecycle_guards(db, original_image, recompiled_image, report)

    assert db.get(ImageId.ORIG, initialization_guard) is None
    assert report.call_count == 1
    assert report.call_args.args == (ReccmpEvent.GENERAL_WARNING, 0x40)
    assert "Skipped Delphi lifecycle guard for Unit1" in report.call_args.kwargs["msg"]


@pytest.mark.parametrize(
    ("original_name", "recompiled_name"),
    [
        ("system.@ClassCreate_00404704", "System.ClassCreate"),
        ("system.@AfterConstruction_0040475C", "System.AfterConstruction"),
        ("system.@BeforeDestruction_0040476C", "System.BeforeDestruction"),
        ("system.@ClassDestroy_00404754", "System.ClassDestroy"),
        ("System.@LStrClr", "System.LStrClr"),
        ("System.@RandInt", "System.RandInt"),
    ],
)
def test_match_functions_delphi_runtime_alias(db: EntityDb, original_name: str, recompiled_name: str):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            123,
            name=original_name,
            type=EntityType.FUNCTION,
        )
        batch.set(
            ImageId.RECOMP,
            555,
            name=recompiled_name,
            type=EntityType.FUNCTION,
        )

    match_functions(db)

    match = db.get(ImageId.ORIG, 123)
    assert match is not None
    assert match.recomp_addr == 555
    assert match.name == recompiled_name


def test_match_functions_does_not_casefold_non_delphi_names(db: EntityDb):
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 123, name="Widget", type=EntityType.FUNCTION)
        batch.set(ImageId.RECOMP, 555, name="widget", type=EntityType.FUNCTION)

    match_functions(db)

    match = db.get(ImageId.ORIG, 123)
    assert match is not None
    assert match.recomp_addr is None


def test_match_functions_does_not_strip_plain_address_suffix(db: EntityDb):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            123,
            name="Widget_12345678",
            type=EntityType.FUNCTION,
        )
        batch.set(ImageId.RECOMP, 555, name="Widget", type=EntityType.FUNCTION)

    match_functions(db)

    match = db.get(ImageId.ORIG, 123)
    assert match is not None
    assert match.recomp_addr is None


def test_match_delphi_library_function_with_verified_address_suffix(db: EntityDb):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            0x12345678,
            name="system.@LibraryHelper_12345678",
            type=EntityType.FUNCTION,
            library=True,
            size=17,
        )
        batch.set(
            ImageId.RECOMP,
            0x5000,
            name="System.LibraryHelper",
            owner_unit="System",
            type=EntityType.FUNCTION,
            is_delphi=True,
            size=17,
        )

    match_delphi_library_functions(db)

    match = db.get(ImageId.ORIG, 0x12345678)
    assert match is not None
    assert match.recomp_addr == 0x5000


def test_match_delphi_library_function_rejects_wrong_suffix_and_application(
    db: EntityDb,
):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            0x12345678,
            name="System.Wrong_12345679",
            type=EntityType.FUNCTION,
            library=True,
        )
        batch.set(
            ImageId.ORIG,
            0x2000,
            name="System.Application_00002000",
            type=EntityType.FUNCTION,
        )
        batch.set(
            ImageId.RECOMP,
            0x5000,
            name="System.Wrong",
            owner_unit="System",
            type=EntityType.FUNCTION,
            is_delphi=True,
        )
        batch.set(
            ImageId.RECOMP,
            0x6000,
            name="System.Application",
            owner_unit="System",
            type=EntityType.FUNCTION,
            is_delphi=True,
        )

    match_delphi_library_functions(db)

    assert db.get(ImageId.ORIG, 0x12345678).recomp_addr is None
    assert db.get(ImageId.ORIG, 0x2000).recomp_addr is None


def test_match_delphi_library_overloads_by_unique_positive_size(db: EntityDb):
    with db.batch() as batch:
        for address, size in ((0x1000, 17), (0x1100, 31)):
            batch.set(
                ImageId.ORIG,
                address,
                name=f"System.Trim_{address:08X}",
                type=EntityType.FUNCTION,
                library=True,
                size=size,
            )
        for address, size in ((0x5000, 31), (0x5100, 17)):
            batch.set(
                ImageId.RECOMP,
                address,
                name="System.Trim",
                owner_unit="System",
                type=EntityType.FUNCTION,
                is_delphi=True,
                size=size,
            )

    match_delphi_library_functions(db)

    assert db.get(ImageId.ORIG, 0x1000).recomp_addr == 0x5100
    assert db.get(ImageId.ORIG, 0x1100).recomp_addr == 0x5000


def test_exact_match_defers_ambiguous_delphi_library_group_to_size_pass(
    db: EntityDb,
):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            0x1000,
            name="System.FinalizeArray",
            type=EntityType.FUNCTION,
            library=True,
            size=58,
        )
        for address, size in ((0x5000, 6), (0x5100, 58)):
            batch.set(
                ImageId.RECOMP,
                address,
                name="System.FinalizeArray",
                owner_unit="System",
                type=EntityType.FUNCTION,
                is_delphi=True,
                size=size,
            )

    match_functions(db)
    assert db.get(ImageId.ORIG, 0x1000).recomp_addr is None

    match_delphi_library_functions(db)
    assert db.get(ImageId.ORIG, 0x1000).recomp_addr == 0x5100


def test_match_delphi_library_overload_ambiguity_is_reported(db: EntityDb):
    with db.batch() as batch:
        for address in (0x1000, 0x1100):
            batch.set(
                ImageId.ORIG,
                address,
                name=f"System.Same_{address:08X}",
                type=EntityType.FUNCTION,
                library=True,
                size=17,
            )
        for address in (0x5000, 0x5100):
            batch.set(
                ImageId.RECOMP,
                address,
                name="System.Same",
                owner_unit="System",
                type=EntityType.FUNCTION,
                is_delphi=True,
                size=17,
            )
    report = Mock(spec=ReccmpReportProtocol)

    match_delphi_library_functions(db, report)

    assert db.get(ImageId.ORIG, 0x1000).recomp_addr is None
    assert db.get(ImageId.ORIG, 0x1100).recomp_addr is None
    report.assert_called_once()
    assert report.call_args.args == (ReccmpEvent.AMBIGUOUS_MATCH, 0x1000)


def _library_layout_images(
    *,
    hidden_recompiled_bytes: bytes = b"\x55\x8b\xec\xc3",
    recompiled_executable: bool = True,
    duplicate_fingerprint: bool = False,
    original_parent_bytes: bytes = b"",
    recompiled_parent_bytes: bytes = b"",
) -> tuple[RawImage, RawImage]:
    original_memory = bytearray(0x100)
    recompiled_memory = bytearray(0x100)
    original_memory[0x20:0x24] = b"\x55\x8b\xec\xc3"
    original_memory[0x10 : 0x10 + len(original_parent_bytes)] = original_parent_bytes
    recompiled_memory[0x60 : 0x60 + len(hidden_recompiled_bytes)] = hidden_recompiled_bytes
    recompiled_memory[0x50 : 0x50 + len(recompiled_parent_bytes)] = recompiled_parent_bytes
    if duplicate_fingerprint:
        recompiled_memory[0x68 : 0x68 + len(hidden_recompiled_bytes)] = hidden_recompiled_bytes
    original = RawImage.from_memory(bytes(original_memory))
    recompiled = RawImage.from_memory(bytes(recompiled_memory))
    original.sections = (
        ImageSection(
            virtual_range=range(0, 0x100),
            physical_range=range(0, 0x100),
            view=original.view,
            name=".text",
            flags=ImageSectionFlags.READ | ImageSectionFlags.EXECUTE,
        ),
    )
    recompiled.sections = (
        ImageSection(
            virtual_range=range(0, 0x100),
            physical_range=range(0, 0x100),
            view=recompiled.view,
            name=".text",
            flags=(
                ImageSectionFlags.READ | ImageSectionFlags.EXECUTE if recompiled_executable else ImageSectionFlags.READ
            ),
        ),
    )
    return original, recompiled


def _add_library_layout_span(db: EntityDb, *, next_recompiled: int = 0x70, hidden_size: int | None = 4):
    with db.batch() as batch:
        for original, recompiled, name in (
            (0x10, 0x50, "Before"),
            (0x30, next_recompiled, "After"),
        ):
            batch.set(
                ImageId.ORIG,
                original,
                name=f"System.{name}",
                type=EntityType.FUNCTION,
                library=True,
                size=4,
            )
            batch.set(
                ImageId.RECOMP,
                recompiled,
                name=f"System.{name}",
                owner_unit="System",
                type=EntityType.FUNCTION,
                is_delphi=True,
                size=4,
            )
            batch.match(original, recompiled)
        batch.set(
            ImageId.ORIG,
            0x20,
            name="system.Hidden_00000020",
            type=EntityType.FUNCTION,
            library=True,
            size=hidden_size,
            max_size=4,
        )


def test_match_delphi_library_boundary_inside_stable_layout(db: EntityDb):
    original, recompiled = _library_layout_images()
    _add_library_layout_span(db)

    match_delphi_library_layout(db, original, recompiled)

    match = db.get(ImageId.ORIG, 0x20)
    assert match is not None
    assert match.recomp_addr == 0x60
    assert match.name == "system.Hidden"
    assert match.get("owner_unit") == "system"
    assert match.get("library_boundary") is True
    assert match.size(ImageId.RECOMP) == 4


def test_match_delphi_library_boundary_uses_inferred_original_size(db: EntityDb):
    original, recompiled = _library_layout_images()
    _add_library_layout_span(db, hidden_size=None)

    match_delphi_library_layout(db, original, recompiled)

    match = db.get(ImageId.ORIG, 0x20)
    assert match is not None
    assert match.recomp_addr == 0x60
    assert match.size(ImageId.RECOMP) == 4


def test_match_delphi_library_boundary_uses_unique_fingerprint_after_layout_break(
    db: EntityDb,
):
    original, recompiled = _library_layout_images()
    _add_library_layout_span(db, next_recompiled=0x74, hidden_size=0x18)
    with db.batch() as batch:
        # TD32 can expose a single oversized function covering hidden static
        # entries. Fingerprint recovery is restricted to instruction
        # boundaries inside that proven owner range.
        batch.set(ImageId.ORIG, 0x10, size=0x14)
        batch.set(ImageId.RECOMP, 0x50, size=0x24)

    match_delphi_library_layout(db, original, recompiled)

    assert db.get(ImageId.ORIG, 0x20).recomp_addr == 0x60
    assert db.get(ImageId.ORIG, 0x10).size(ImageId.ORIG) == 0x10
    assert db.get(ImageId.ORIG, 0x20).size(ImageId.ORIG) == 0x10
    assert db.get(ImageId.RECOMP, 0x50).size(ImageId.RECOMP) == 0x10
    synthetic_boundary = db.get(ImageId.RECOMP, 0x60)
    assert synthetic_boundary is not None
    assert synthetic_boundary.size(ImageId.RECOMP) == 0x14


def test_match_delphi_library_boundary_rejects_conflicting_owner(db: EntityDb):
    original, recompiled = _library_layout_images()
    _add_library_layout_span(db)
    with db.batch() as batch:
        batch.set(
            ImageId.RECOMP,
            0x60,
            name="SysUtils.Unrelated",
            owner_unit="SysUtils",
            type=EntityType.FUNCTION,
            is_delphi=True,
            size=4,
        )

    match_delphi_library_layout(db, original, recompiled)

    assert db.get(ImageId.ORIG, 0x20).recomp_addr is None


def test_match_delphi_library_boundary_maps_parent_jump_alternate_entry(
    db: EntityDb,
):
    original, recompiled = _library_layout_images(
        hidden_recompiled_bytes=b"\x8b\x04\x24\xc3",
        original_parent_bytes=b"\xeb\x0e",
        recompiled_parent_bytes=b"\x51\xeb\x0d",
    )
    with db.batch() as batch:
        for original_address, recompiled_address, name, size in (
            (0x10, 0x50, "Before", 0x10),
            (0x30, 0x74, "After", 4),
        ):
            batch.set(
                ImageId.ORIG,
                original_address,
                name=f"System.{name}",
                type=EntityType.FUNCTION,
                library=True,
                size=size,
            )
            batch.set(
                ImageId.RECOMP,
                recompiled_address,
                name=f"System.{name}",
                owner_unit="System",
                type=EntityType.FUNCTION,
                is_delphi=True,
                size=size,
            )
            batch.match(original_address, recompiled_address)
        # The original TD32 range can cover only the two-byte JMP while its
        # target is exposed as the adjacent alternate entry.
        batch.set(ImageId.ORIG, 0x10, size=2)
        batch.set(
            ImageId.ORIG,
            0x20,
            name="System.Hidden_00000020",
            type=EntityType.FUNCTION,
            library=True,
            size=4,
        )

    match_delphi_library_layout(db, original, recompiled)

    assert db.get(ImageId.ORIG, 0x20).recomp_addr == 0x60


def test_match_delphi_library_boundary_uses_corresponding_first_parent_jump(
    db: EntityDb,
):
    original, recompiled = _library_layout_images(
        hidden_recompiled_bytes=b"\x8b\x04\x24\xc3",
        original_parent_bytes=b"\xeb\x0e",
        # The first JMP enters the moved loop body at 0x60. A later JMP to
        # 0x64 is another valid local target and must not make this ambiguous.
        recompiled_parent_bytes=b"\x51\xeb\x0d\xeb\x0f",
    )
    with db.batch() as batch:
        for original_address, recompiled_address, name, size in (
            (0x10, 0x50, "Before", 0x10),
            (0x30, 0x74, "After", 4),
        ):
            batch.set(
                ImageId.ORIG,
                original_address,
                name=f"System.{name}",
                type=EntityType.FUNCTION,
                library=True,
                size=size,
            )
            batch.set(
                ImageId.RECOMP,
                recompiled_address,
                name=f"System.{name}",
                owner_unit="System",
                type=EntityType.FUNCTION,
                is_delphi=True,
                size=size,
            )
            batch.match(original_address, recompiled_address)
        batch.set(
            ImageId.ORIG,
            0x20,
            name="System.Hidden_00000020",
            type=EntityType.FUNCTION,
            library=True,
            size=4,
        )

    match_delphi_library_layout(db, original, recompiled)

    assert db.get(ImageId.ORIG, 0x20).recomp_addr == 0x60


@pytest.mark.parametrize("duplicate_fingerprint", [False, True])
def test_match_delphi_library_boundary_rejects_unsafe_fingerprint(db: EntityDb, duplicate_fingerprint: bool):
    original, recompiled = _library_layout_images(
        recompiled_executable=duplicate_fingerprint,
        duplicate_fingerprint=duplicate_fingerprint,
    )
    _add_library_layout_span(db, next_recompiled=0x74)

    match_delphi_library_layout(db, original, recompiled)

    assert db.get(ImageId.ORIG, 0x20).recomp_addr is None


def add_delphi_placeholder_span(
    db: EntityDb,
    *,
    previous_recomp: int = 0x2000,
    candidate_size: int = 198,
    candidate_owner: str = "System",
):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            0x1000,
            type=EntityType.FUNCTION,
            name="System.Before",
            size=10,
        )
        batch.set(
            ImageId.RECOMP,
            previous_recomp,
            type=EntityType.FUNCTION,
            name="System.Before",
            size=10,
            owner_unit="System",
            is_delphi=True,
        )
        batch.match(0x1000, previous_recomp)

        batch.set(
            ImageId.ORIG,
            0x1100,
            type=EntityType.FUNCTION,
            name="system.sub_00001100_00001100",
            size=198,
        )
        batch.set(
            ImageId.RECOMP,
            0x2100,
            type=EntityType.FUNCTION,
            name="System.FreeSpace",
            size=candidate_size,
            owner_unit=candidate_owner,
            is_delphi=True,
        )

        batch.set(
            ImageId.ORIG,
            0x1200,
            type=EntityType.FUNCTION,
            name="System.After",
            size=10,
        )
        batch.set(
            ImageId.RECOMP,
            0x2200,
            type=EntityType.FUNCTION,
            name="System.After",
            size=10,
            owner_unit="System",
            is_delphi=True,
        )
        batch.match(0x1200, 0x2200)


def test_match_delphi_idr_placeholder_inside_stable_layout_span(db: EntityDb):
    add_delphi_placeholder_span(db)

    match_delphi_idr_placeholders(db)

    match = db.get(ImageId.ORIG, 0x1100)
    assert match is not None
    assert match.recomp_addr == 0x2100
    assert match.get("name") == "System.FreeSpace"


@pytest.mark.parametrize(
    ("previous_recomp", "candidate_size", "candidate_owner", "placeholder_name"),
    [
        (0x1FF0, 198, "System", "system.sub_00001100_00001100"),
        (0x2000, 197, "System", "system.sub_00001100_00001100"),
        (0x2000, 198, "SysUtils", "system.sub_00001100_00001100"),
        (0x2000, 198, "System", "system.sub_00001104_00001104"),
    ],
)
def test_match_delphi_idr_placeholder_rejects_unsafe_inference(
    db: EntityDb,
    previous_recomp: int,
    candidate_size: int,
    candidate_owner: str,
    placeholder_name: str,
):
    add_delphi_placeholder_span(
        db,
        previous_recomp=previous_recomp,
        candidate_size=candidate_size,
        candidate_owner=candidate_owner,
    )
    if placeholder_name != "system.sub_00001100_00001100":
        with db.batch() as batch:
            batch.set(ImageId.ORIG, 0x1100, name=placeholder_name)

    match_delphi_idr_placeholders(db)

    assert not db.is_match(0x1100, 0x2100)


def test_match_vtables_delphi_unit_qualified_marker_with_short_td32_name(
    db: EntityDb,
):
    """Delphi source markers retain the owner unit even when TD32 does not."""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            100,
            name="Unit1.TWidget",
            type=EntityType.VTABLE,
        )
        batch.set(
            ImageId.RECOMP,
            200,
            name="TWidget",
            type=EntityType.VTABLE,
            is_delphi=True,
        )

    match_vtables(db)

    match = db.get(ImageId.ORIG, 100)
    assert match is not None
    assert match.recomp_addr == 200


def test_match_vtables_delphi_short_name_must_be_unique(db: EntityDb):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            100,
            name="Unit1.TWidget",
            type=EntityType.VTABLE,
        )
        batch.set(
            ImageId.RECOMP,
            200,
            name="TWidget",
            type=EntityType.VTABLE,
            is_delphi=True,
        )
        batch.set(
            ImageId.RECOMP,
            300,
            name="TWidget",
            type=EntityType.VTABLE,
            is_delphi=True,
        )

    match_vtables(db)

    match = db.get(ImageId.ORIG, 100)
    assert match is not None
    assert match.recomp_addr is None
