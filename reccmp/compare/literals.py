"""Read anonymous, non-relocated scalar constants from PE images."""

from bisect import bisect_left
from functools import cache

from reccmp.compare.asm.literals import LiteralLookup
from reccmp.compare.db import EntityDb
from reccmp.formats import Image, PEImage
from reccmp.formats.exceptions import (
    InvalidVirtualAddressError,
    InvalidVirtualReadError,
)
from reccmp.formats.image import ImageSectionFlags
from reccmp.types import EntityType, ImageId


def create_literal_lookup(
    db: EntityDb, image_id: ImageId, image: Image
) -> LiteralLookup | None:
    """Read only proven, unnamed scalar storage; never infer a global match.

    PE supplies both section permissions and 32-bit base relocation sites. A
    relocation overlapping any byte of the read makes it unsuitable for raw
    value comparison. Other image formats need equivalent evidence first.
    """
    if not isinstance(image, PEImage):
        return None

    relocation_sites = tuple(sorted(image.relocations))

    @cache
    def occupied_ranges() -> tuple[tuple[tuple[int, int, bool], ...], tuple[int, ...]]:
        # The comparator is constructed before symbol ingestion. Build this
        # index lazily, once comparisons start and the entity database is ready.
        # Prefix maxima let us find enclosing entities even behind local labels.
        ranges: list[tuple[int, int, bool]] = []
        max_ends: list[int] = []
        for entity in db.all(image_id):
            start = entity.addr(image_id)
            assert start is not None
            # max_size includes gaps, including Delphi's trailing literal pools.
            end = start + max(1, entity.any_size(image_id))
            ranges.append((start, end, entity.entity_type == EntityType.FUNCTION))
            max_ends.append(max(end, max_ends[-1] if max_ends else end))
        return tuple(ranges), tuple(max_ends)

    @cache
    def lookup(
        addr: int, size: int, owning_function: int | None = None
    ) -> bytes | None:
        section = next(
            (section for section in image.sections if section.contains_vaddr(addr)),
            None,
        )
        if section is None or size not in (1, 2, 4, 8, 10):
            return None
        if (
            ImageSectionFlags.READ not in section.flags
            or ImageSectionFlags.WRITE in section.flags
            or ImageSectionFlags.BSS in section.flags
            or not section.contains_vaddr(addr + size - 1)
            or addr + size > section.virtual_address + len(section.view)
        ):
            return None

        # A read may start inside the four bytes covered by a relocation.
        index = bisect_left(relocation_sites, addr - 3)
        if index < len(relocation_sites) and relocation_sites[index] < addr + size:
            return None

        ranges, max_ends = occupied_ranges()
        # Last entity range starting before the exclusive end of this read.
        index = bisect_left(ranges, addr + size, key=lambda row: row[0]) - 1
        while index >= 0 and max_ends[index] > addr:
            start, end, is_function = ranges[index]
            # A procedure's debug size can include its trailing literal pool.
            # ParseAsm separately excludes its actual decoded instructions.
            if end > addr and not (is_function and start == owning_function):
                return None
            index -= 1

        try:
            data = image.read(addr, size)
        except (InvalidVirtualAddressError, InvalidVirtualReadError):
            return None
        return bytes(data) if len(data) == size else None

    return lookup
