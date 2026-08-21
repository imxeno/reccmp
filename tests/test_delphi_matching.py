"""Tests for matching Delphi names and VMTs across analysis sources."""

import pytest

from reccmp.compare.db import EntityDb
from reccmp.compare.match_msvc import (
    match_delphi_idr_placeholders,
    match_functions,
    match_vtables,
)
from reccmp.types import EntityType, ImageId


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


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
def test_match_functions_delphi_runtime_alias(
    db: EntityDb, original_name: str, recompiled_name: str
):
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
