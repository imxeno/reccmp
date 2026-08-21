"""Structural matching for Delphi compiler and library entities."""

from collections import defaultdict
from collections.abc import Callable
from bisect import bisect_left
import re

from capstone import (  # type: ignore
    CS_ARCH_X86,
    CS_MODE_32,
    CS_OP_IMM,
    CS_OP_MEM,
    CS_OP_REG,
    Cs,
)

from reccmp.formats.image import Image, ImageSectionFlags
from reccmp.types import EntityType, ImageId

from .db import EntityDb, ReccmpEntity, ReccmpMatch
from .event import ReccmpEvent, ReccmpReportProtocol, reccmp_report_nop

MAX_LIFECYCLE_FUNCTION_SIZE = 512
DELPHI_LIBRARY_ADDRESS_SUFFIX_RE = re.compile(r"_([0-9a-f]{8})$", re.IGNORECASE)


def _canonical_original_library_name(entity: ReccmpEntity) -> str | None:
    """Return a safe case-insensitive key for an original library function.

    IDR appends an address to many otherwise canonical Delphi names.  Accept
    that suffix only when it encodes the entity's actual original address;
    otherwise leave the row unmatched rather than silently discarding data.
    """

    name = entity.name
    if not isinstance(name, str) or entity.orig_addr is None:
        return None

    suffix = DELPHI_LIBRARY_ADDRESS_SUFFIX_RE.search(name)
    if suffix is not None:
        if int(suffix.group(1), 16) != entity.orig_addr:
            return None
        name = name[: suffix.start()]

    # Delphi identifiers are case-insensitive.  TD32 also omits IDR's ``@``
    # compiler decoration from individual qualified-name components.
    name = ".".join(part.removeprefix("@") for part in name.split("."))
    return name.rstrip(".").casefold()


def _canonical_recompiled_library_name(entity: ReccmpEntity) -> str | None:
    name = entity.name
    owner_unit = entity.get("owner_unit")
    if not entity.get("is_delphi") or not isinstance(name, str) or not isinstance(owner_unit, str):
        return None

    if not name.casefold().startswith(f"{owner_unit}.".casefold()):
        name = f"{owner_unit}.{name}"
    name = ".".join(part.removeprefix("@") for part in name.split("."))
    return name.rstrip(".").casefold()


def match_delphi_library_functions(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    """Match canonical Delphi runtime/library names after exact matching.

    This deliberately excludes application functions.  Unique qualified names
    match directly.  Duplicate overload groups are paired only where a positive
    function size occurs exactly once on both images; unresolved members remain
    available to the later structural-layout matcher.
    """

    original_groups: defaultdict[str, list[ReccmpEntity]] = defaultdict(list)
    recompiled_groups: defaultdict[str, list[ReccmpEntity]] = defaultdict(list)

    for entity in db.unmatched(ImageId.ORIG):
        if entity.entity_type != EntityType.FUNCTION or not entity.get("library"):
            continue
        key = _canonical_original_library_name(entity)
        if key is not None:
            original_groups[key].append(entity)

    for entity in db.unmatched(ImageId.RECOMP):
        if entity.entity_type != EntityType.FUNCTION:
            continue
        key = _canonical_recompiled_library_name(entity)
        if key is not None:
            recompiled_groups[key].append(entity)

    pairs: list[tuple[int, int]] = []
    for key, originals in original_groups.items():
        candidates = recompiled_groups.get(key, [])
        if not candidates:
            continue

        if len(originals) == 1 and len(candidates) == 1:
            original_address = originals[0].orig_addr
            recompiled_address = candidates[0].recomp_addr
            assert original_address is not None and recompiled_address is not None
            pairs.append((original_address, recompiled_address))
            continue

        originals_by_size: defaultdict[int, list[ReccmpEntity]] = defaultdict(list)
        candidates_by_size: defaultdict[int, list[ReccmpEntity]] = defaultdict(list)
        for entity in originals:
            size = entity.size(ImageId.ORIG)
            if size is not None and size > 0:
                originals_by_size[size].append(entity)
        for entity in candidates:
            size = entity.size(ImageId.RECOMP)
            if size is not None and size > 0:
                candidates_by_size[size].append(entity)

        resolved = 0
        for size, sized_originals in originals_by_size.items():
            sized_candidates = candidates_by_size.get(size, [])
            if len(sized_originals) != 1 or len(sized_candidates) != 1:
                continue
            original_address = sized_originals[0].orig_addr
            recompiled_address = sized_candidates[0].recomp_addr
            assert original_address is not None and recompiled_address is not None
            pairs.append((original_address, recompiled_address))
            resolved += 1

        if resolved < min(len(originals), len(candidates)):
            first_address = originals[0].orig_addr
            assert first_address is not None
            report(
                ReccmpEvent.AMBIGUOUS_MATCH,
                first_address,
                msg=(
                    "Ambiguous Delphi library group "
                    f"'{key}' ({len(originals)} original, "
                    f"{len(candidates)} recompiled; {resolved} size-resolved)"
                ),
            )

    db.bulk_match(pairs)


def _canonical_original_library_spelling(entity: ReccmpEntity) -> str | None:
    name = entity.name
    if not isinstance(name, str) or entity.orig_addr is None:
        return None

    suffix = DELPHI_LIBRARY_ADDRESS_SUFFIX_RE.search(name)
    if suffix is not None:
        if int(suffix.group(1), 16) != entity.orig_addr:
            return None
        name = name[: suffix.start()]

    return ".".join(part.removeprefix("@") for part in name.split(".")).rstrip(".")


def _instruction_operand_shape(instruction, operand) -> tuple:
    if operand.type == CS_OP_REG:
        return (CS_OP_REG, instruction.reg_name(operand.reg))
    if operand.type == CS_OP_IMM:
        # Absolute addresses and relative branch displacements relocate.
        return (CS_OP_IMM, operand.size)
    if operand.type == CS_OP_MEM:
        memory = operand.mem
        displacement = memory.disp if memory.base != 0 or memory.index != 0 else 0
        return (
            CS_OP_MEM,
            instruction.reg_name(memory.base),
            instruction.reg_name(memory.index),
            memory.scale,
            displacement,
            operand.size,
        )
    return (operand.type, operand.size)


def _instruction_shapes(image: Image, address: int, count: int = 2) -> tuple | None:
    try:
        blob = image.read(address, 32)
    except (IndexError, ValueError, OSError):
        return None

    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    shapes = []
    for instruction in disassembler.disasm(blob, address):
        shapes.append(
            (
                instruction.mnemonic,
                tuple(_instruction_operand_shape(instruction, operand) for operand in instruction.operands),
            )
        )
        if len(shapes) == count or instruction.mnemonic.startswith("ret"):
            break

    return tuple(shapes) if shapes else None


def _is_relocated_operand(image: Image, address: int) -> bool:
    try:
        return image.is_relocated_addr(address)
    except (NotImplementedError, IndexError, ValueError):
        return False


def _instruction_fingerprint_operand(image: Image, instruction, operand) -> tuple:
    if operand.type == CS_OP_REG:
        return (CS_OP_REG, instruction.reg_name(operand.reg))

    if operand.type == CS_OP_IMM:
        relocation_site = instruction.address + instruction.imm_offset
        if (
            instruction.mnemonic == "call"
            or instruction.mnemonic.startswith("j")
            or _is_relocated_operand(image, relocation_site)
        ):
            return (CS_OP_IMM, "target", operand.size)
        return (CS_OP_IMM, operand.imm, operand.size)

    if operand.type == CS_OP_MEM:
        memory = operand.mem
        displacement: int | str = memory.disp
        relocation_site = instruction.address + instruction.disp_offset
        if memory.base == 0 and memory.index == 0 and _is_relocated_operand(image, relocation_site):
            displacement = "address"
        return (
            CS_OP_MEM,
            instruction.reg_name(memory.base),
            instruction.reg_name(memory.index),
            memory.scale,
            displacement,
            operand.size,
        )

    return (operand.type, operand.size)


def _instruction_fingerprint(image: Image, address: int, size: int, count: int = 8) -> tuple | None:
    if size <= 0:
        return None
    try:
        blob = image.read(address, min(size, 96))
    except (IndexError, ValueError, OSError):
        return None

    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    fingerprint = []
    for instruction in disassembler.disasm(blob, address):
        fingerprint.append(
            (
                instruction.mnemonic,
                tuple(
                    _instruction_fingerprint_operand(image, instruction, operand) for operand in instruction.operands
                ),
            )
        )
        if len(fingerprint) == count or instruction.mnemonic.startswith("ret"):
            break

    return tuple(fingerprint) if fingerprint else None


def _direct_local_jump_targets(image: Image, address: int, size: int) -> set[int]:
    if size <= 0:
        return set()
    try:
        blob = image.read(address, min(size, 96))
    except (IndexError, ValueError, OSError):
        return set()

    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    result: set[int] = set()
    for instruction in disassembler.disasm(blob, address):
        if (
            instruction.mnemonic == "jmp"
            and len(instruction.operands) == 1
            and instruction.operands[0].type == CS_OP_IMM
        ):
            target = instruction.operands[0].imm
            if address <= target <= address + size:
                result.add(target)
    return result


def _first_direct_local_jump_target(image: Image, address: int, size: int) -> int | None:
    """Return the first direct local JMP target in instruction order."""

    if size <= 0:
        return None
    try:
        blob = image.read(address, min(size, 96))
    except (IndexError, ValueError, OSError):
        return None

    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    for instruction in disassembler.disasm(blob, address):
        if (
            instruction.mnemonic == "jmp"
            and len(instruction.operands) == 1
            and instruction.operands[0].type == CS_OP_IMM
        ):
            target = instruction.operands[0].imm
            # The reported parent can be only the initial JMP instruction;
            # its compiler loop header is then represented as a separate entry
            # beyond that short range. The caller proves the target is the
            # adjacent unmatched entry before associating it.
            return target
    return None


def _direct_control_targets(image: Image, address: int, size: int) -> tuple[tuple[str, int], ...]:
    if size <= 0:
        return tuple()
    try:
        blob = image.read(address, min(size, 96))
    except (IndexError, ValueError, OSError):
        return tuple()

    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    result = []
    for instruction in disassembler.disasm(blob, address):
        if (
            (instruction.mnemonic == "call" or instruction.mnemonic.startswith("j"))
            and len(instruction.operands) == 1
            and instruction.operands[0].type == CS_OP_IMM
        ):
            result.append((instruction.mnemonic, instruction.operands[0].imm))
    return tuple(result)


def _mapped_original_control_targets(
    db: EntityDb, image: Image, address: int, size: int
) -> tuple[tuple[str, int], ...] | None:
    mapped = []
    for mnemonic, target in _direct_control_targets(image, address, size):
        target_match = db.get_one_match(target)
        if target_match is None:
            return None
        mapped.append((mnemonic, target_match.recomp_addr))
    return tuple(mapped) if mapped else None


def _is_executable_range(image: Image, address: int, size: int) -> bool:
    if size <= 0:
        return False
    matches = [
        section
        for section in image.sections
        if address in section.virtual_range
        and address + size - 1 in section.virtual_range
        and section.flags & ImageSectionFlags.EXECUTE
    ]
    return len(matches) == 1


def _library_candidate_at(db: EntityDb, address: int, owner_key: str) -> tuple[bool, ReccmpEntity | None]:
    candidate = db.get(ImageId.RECOMP, address)
    if candidate is not None:
        candidate_owner = candidate.get("owner_unit")
        valid = (
            not candidate.matched
            and candidate.entity_type == EntityType.FUNCTION
            and candidate.get("is_delphi")
            and isinstance(candidate_owner, str)
            and candidate_owner.casefold() == owner_key
        )
        return valid, candidate

    containing = db.get(ImageId.RECOMP, address, exact=False)
    containing_owner = containing.get("owner_unit") if containing is not None else None
    containing_size = (
        (containing.size(ImageId.RECOMP) or containing.max_size(ImageId.RECOMP) or 0) if containing is not None else 0
    )
    valid = (
        containing is not None
        and containing.recomp_addr is not None
        and containing.recomp_addr < address
        and address <= containing.recomp_addr + containing_size
        and containing.get("is_delphi")
        and isinstance(containing_owner, str)
        and containing_owner.casefold() == owner_key
    )
    return valid, None


LibraryBoundaryProposal = tuple[ReccmpEntity, int, str, str, ReccmpEntity | None]


def _apply_library_boundary_proposals(
    db: EntityDb,
    proposals: list[LibraryBoundaryProposal],
    report: ReccmpReportProtocol,
    reason: str,
):
    if not proposals:
        return

    proposals.sort(key=lambda item: item[1])
    with db.batch() as batch:
        for entity, recompiled_address, spelling, owner_unit, candidate in proposals:
            assert entity.orig_addr is not None
            inferred_size = entity.size(ImageId.ORIG) or entity.max_size(ImageId.ORIG) or 0
            if candidate is None:
                batch.set(
                    ImageId.RECOMP,
                    recompiled_address,
                    type=EntityType.FUNCTION,
                    name=spelling,
                    size=inferred_size,
                    owner_unit=owner_unit,
                    is_delphi=True,
                    library_boundary=True,
                )
            batch.match(entity.orig_addr, recompiled_address)

            previous = db.get(ImageId.RECOMP, recompiled_address, exact=False)
            previous_owner = previous.get("owner_unit") if previous is not None else None
            if (
                previous is not None
                and previous.recomp_addr is not None
                and previous.recomp_addr < recompiled_address
                and isinstance(previous_owner, str)
                and previous_owner.casefold() == owner_unit.casefold()
                and (previous.size(ImageId.RECOMP) or 0) > recompiled_address - previous.recomp_addr
            ):
                batch.set(
                    ImageId.RECOMP,
                    previous.recomp_addr,
                    size=recompiled_address - previous.recomp_addr,
                )

    for entity, recompiled_address, spelling, _, _ in proposals:
        assert entity.orig_addr is not None
        report(
            ReccmpEvent.GENERAL_WARNING,
            entity.orig_addr,
            msg=(f"Matched Delphi library boundary '{spelling}' at " f"0x{recompiled_address:x} from {reason}"),
        )


def match_delphi_library_layout(
    db: EntityDb,
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol = reccmp_report_nop,
):  # pylint: disable=too-many-locals
    """Recover library boundaries inside stable Delphi unit layout spans.

    A projected entry needs matched library anchors on both sides, identical
    displacement at those anchors, matching instruction shapes at the proposed
    boundary, and a conflict-free executable target.  This supports compiler
    and static/nested library functions that TD32 groups into a larger range.
    """

    anchors_by_owner: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
    for match in db.get_functions():
        owner_unit = match.get("owner_unit")
        if match.get("library") and match.get("is_delphi") and isinstance(owner_unit, str):
            anchors_by_owner[owner_unit.casefold()].append((match.orig_addr, match.recomp_addr))
    for anchors in anchors_by_owner.values():
        anchors.sort()

    proposals: list[LibraryBoundaryProposal] = []
    proposed_recompiled_addresses: set[int] = set()

    for entity in db.unmatched(ImageId.ORIG):
        if entity.entity_type != EntityType.FUNCTION or not entity.get("library"):
            continue

        spelling = _canonical_original_library_spelling(entity)
        if spelling is None or "." not in spelling:
            continue
        owner_unit = spelling.split(".", 1)[0]
        anchors = anchors_by_owner.get(owner_unit.casefold(), [])
        if len(anchors) < 2 or entity.orig_addr is None:
            continue

        original_addresses = [address for address, _ in anchors]
        insertion_index = bisect_left(original_addresses, entity.orig_addr)
        if insertion_index == 0 or insertion_index == len(anchors):
            continue

        previous_original, previous_recompiled = anchors[insertion_index - 1]
        next_original, next_recompiled = anchors[insertion_index]
        previous_displacement = previous_recompiled - previous_original
        next_displacement = next_recompiled - next_original
        if previous_displacement != next_displacement:
            continue

        recompiled_address = entity.orig_addr + previous_displacement
        if (
            recompiled_address <= previous_recompiled
            or recompiled_address >= next_recompiled
            or recompiled_address in proposed_recompiled_addresses
        ):
            continue

        # Library CSV rows commonly omit an explicit size.  ``set_max_size`` has
        # already established the safe distance to the next original entity,
        # so use it as the boundary size when no measured size is available.
        inferred_size = entity.size(ImageId.ORIG) or entity.max_size(ImageId.ORIG) or 0
        if not _is_executable_range(original_image, entity.orig_addr, inferred_size):
            continue
        if not _is_executable_range(recompiled_image, recompiled_address, inferred_size):
            continue
        # The two anchors prove the source-order displacement.  Codegen inside
        # the span may still differ (especially compiler cleanup entries), so
        # require a decodable instruction boundary on both images without
        # requiring identical instructions.
        if _instruction_shapes(original_image, entity.orig_addr) is None or (
            _instruction_shapes(recompiled_image, recompiled_address) is None
        ):
            continue

        candidate = db.get(ImageId.RECOMP, recompiled_address)
        if candidate is not None:
            candidate_owner = candidate.get("owner_unit")
            if (
                candidate.matched
                or candidate.entity_type != EntityType.FUNCTION
                or not candidate.get("is_delphi")
                or not isinstance(candidate_owner, str)
                or candidate_owner.casefold() != owner_unit.casefold()
            ):
                continue

        proposals.append((entity, recompiled_address, spelling, owner_unit, candidate))
        proposed_recompiled_addresses.add(recompiled_address)

    _apply_library_boundary_proposals(db, proposals, report, "stable unit layout")
    _match_delphi_library_alternate_entries(db, original_image, recompiled_image, report)
    _match_delphi_library_fingerprints(db, original_image, recompiled_image, report)
    _split_overlapping_delphi_library_ranges(db)


def _split_overlapping_delphi_library_ranges(db: EntityDb):
    """Clip enclosing Delphi library ranges at every matched local boundary.

    TD32 and IDR can each describe a parent routine as covering nested/static
    entries that are also present in the original inventory. Once those local
    entries have verified matches, comparing the enclosing estimate over the
    same bytes would produce overlapping entities. Split both images at every
    same-unit boundary so each instruction belongs to at most one comparison.
    """

    for image_id in (ImageId.ORIG, ImageId.RECOMP):
        ranges: list[tuple[int, ReccmpMatch]] = []
        for match in db.get_functions():
            owner_unit = match.get("owner_unit")
            address = match.addr(image_id)
            if (
                address is None
                or not match.get("library")
                or not match.get("is_delphi")
                or not isinstance(owner_unit, str)
            ):
                continue
            ranges.append((address, match))

        ranges.sort(key=lambda item: item[0])
        with db.batch() as batch:
            for (address, match), (next_address, next_match) in zip(ranges, ranges[1:]):
                owner_unit = match.get("owner_unit")
                next_owner_unit = next_match.get("owner_unit")
                if (
                    not isinstance(owner_unit, str)
                    or not isinstance(next_owner_unit, str)
                    or owner_unit.casefold() != next_owner_unit.casefold()
                ):
                    continue

                size = match.size(image_id) or 0
                boundary_size = next_address - address
                if boundary_size > 0 and size > boundary_size:
                    batch.set(image_id, address, size=boundary_size)


def _match_delphi_library_alternate_entries(
    db: EntityDb,
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol,
):
    """Map hidden entries reached by a matched parent's local jump."""

    anchors_by_owner: defaultdict[str, list[ReccmpMatch]] = defaultdict(list)
    for match in db.get_functions():
        owner_unit = match.get("owner_unit")
        if match.get("library") and match.get("is_delphi") and isinstance(owner_unit, str):
            anchors_by_owner[owner_unit.casefold()].append(match)
    for anchors in anchors_by_owner.values():
        anchors.sort(key=lambda item: item.orig_addr)

    proposals: list[LibraryBoundaryProposal] = []
    proposed_addresses: set[int] = set()
    for entity in list(db.unmatched(ImageId.ORIG)):
        spelling = _canonical_original_library_spelling(entity)
        if (
            entity.entity_type != EntityType.FUNCTION
            or not entity.get("library")
            or spelling is None
            or "." not in spelling
            or entity.orig_addr is None
        ):
            continue
        owner_unit = spelling.split(".", 1)[0]
        owner_key = owner_unit.casefold()
        anchors = anchors_by_owner.get(owner_key, [])
        previous = next(
            (anchor for anchor in reversed(anchors) if anchor.orig_addr < entity.orig_addr),
            None,
        )
        if previous is None:
            continue

        original_parent_size = previous.max_size(ImageId.ORIG) or previous.size(ImageId.ORIG) or 0
        original_first_target = _first_direct_local_jump_target(
            original_image, previous.orig_addr, original_parent_size
        )
        if entity.orig_addr != original_first_target and entity.orig_addr not in _direct_local_jump_targets(
            original_image, previous.orig_addr, original_parent_size
        ):
            continue

        recompiled_parent_size = previous.size(ImageId.RECOMP) or previous.max_size(ImageId.RECOMP) or 0
        recompiled_first_target = _first_direct_local_jump_target(
            recompiled_image, previous.recomp_addr, recompiled_parent_size
        )
        if (
            original_first_target == entity.orig_addr
            and recompiled_first_target is not None
            and recompiled_first_target not in proposed_addresses
            and _is_executable_range(recompiled_image, recompiled_first_target, 1)
            and _library_candidate_at(db, recompiled_first_target, owner_key)[0]
        ):
            candidates = {recompiled_first_target}
        else:
            candidates = _direct_local_jump_targets(recompiled_image, previous.recomp_addr, recompiled_parent_size)
            candidates = {
                address
                for address in candidates
                if address not in proposed_addresses
                and _is_executable_range(recompiled_image, address, 1)
                and _library_candidate_at(db, address, owner_key)[0]
            }
        if len(candidates) != 1:
            if candidates:
                report(
                    ReccmpEvent.AMBIGUOUS_MATCH,
                    entity.orig_addr,
                    msg=(
                        f"Rejected Delphi alternate entry '{spelling}': " f"found {len(candidates)} local jump targets"
                    ),
                )
            continue

        address = next(iter(candidates))
        _, candidate = _library_candidate_at(db, address, owner_key)
        proposals.append((entity, address, spelling, owner_unit, candidate))
        proposed_addresses.add(address)

    _apply_library_boundary_proposals(db, proposals, report, "matched-parent local control flow")


def _match_delphi_library_fingerprints(
    db: EntityDb,
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol,
):  # pylint: disable=too-many-locals
    """Find layout-break boundaries by unique, unit-scoped code shape."""

    anchors_by_owner: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
    owner_ranges: dict[str, tuple[int, int]] = {}
    owner_instruction_boundaries: defaultdict[str, set[int]] = defaultdict(set)
    boundary_disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    for entity in db.all(ImageId.RECOMP):
        owner_unit = entity.get("owner_unit")
        if (
            entity.entity_type != EntityType.FUNCTION
            or not entity.get("is_delphi")
            or not isinstance(owner_unit, str)
            or entity.recomp_addr is None
        ):
            continue
        owner_key = owner_unit.casefold()
        end = entity.recomp_addr + (entity.size(ImageId.RECOMP) or entity.max_size(ImageId.RECOMP) or 1)
        if owner_key in owner_ranges:
            start, current_end = owner_ranges[owner_key]
            owner_ranges[owner_key] = (
                min(start, entity.recomp_addr),
                max(current_end, end),
            )
        else:
            owner_ranges[owner_key] = (entity.recomp_addr, end)

        size = end - entity.recomp_addr
        try:
            blob = recompiled_image.read(entity.recomp_addr, size)
        except (IndexError, ValueError, OSError):
            continue
        owner_instruction_boundaries[owner_key].update(
            instruction.address for instruction in boundary_disassembler.disasm(blob, entity.recomp_addr)
        )

    ordered_owner_boundaries = {
        owner: tuple(sorted(addresses)) for owner, addresses in owner_instruction_boundaries.items()
    }

    for match in db.get_functions():
        owner_unit = match.get("owner_unit")
        if match.get("library") and match.get("is_delphi") and isinstance(owner_unit, str):
            anchors_by_owner[owner_unit.casefold()].append((match.orig_addr, match.recomp_addr))
    for anchors in anchors_by_owner.values():
        anchors.sort()

    proposals: list[LibraryBoundaryProposal] = []
    proposed_addresses: set[int] = set()
    for entity in list(db.unmatched(ImageId.ORIG)):
        if entity.entity_type != EntityType.FUNCTION or not entity.get("library"):
            continue
        spelling = _canonical_original_library_spelling(entity)
        if spelling is None or "." not in spelling or entity.orig_addr is None:
            continue
        owner_unit = spelling.split(".", 1)[0]
        owner_key = owner_unit.casefold()
        owner_range = owner_ranges.get(owner_key)
        if owner_range is None:
            continue

        size = entity.size(ImageId.ORIG) or entity.max_size(ImageId.ORIG) or 0
        original_fingerprint = _instruction_fingerprint(original_image, entity.orig_addr, size)
        if original_fingerprint is None:
            report(
                ReccmpEvent.GENERAL_WARNING,
                entity.orig_addr,
                msg=f"Rejected Delphi fingerprint for '{spelling}': no original fingerprint",
            )
            continue

        search_start, search_end = owner_range
        anchors = anchors_by_owner.get(owner_key, [])
        original_addresses = [address for address, _ in anchors]
        insertion_index = bisect_left(original_addresses, entity.orig_addr)
        if insertion_index > 0:
            search_start = max(search_start, anchors[insertion_index - 1][1] + 1)
        if insertion_index < len(anchors):
            search_end = min(search_end, anchors[insertion_index][1])
        if search_start >= search_end:
            report(
                ReccmpEvent.GENERAL_WARNING,
                entity.orig_addr,
                msg=f"Rejected Delphi fingerprint for '{spelling}': invalid unit search span",
            )
            continue

        candidates: list[tuple[int, ReccmpEntity | None]] = []
        for candidate_address in ordered_owner_boundaries.get(owner_key, ()):
            if not search_start <= candidate_address < search_end:
                continue
            if candidate_address in proposed_addresses:
                continue
            if not _is_executable_range(recompiled_image, candidate_address, size):
                continue

            valid_candidate, candidate = _library_candidate_at(db, candidate_address, owner_key)
            if not valid_candidate:
                continue

            if _instruction_fingerprint(recompiled_image, candidate_address, size) == original_fingerprint:
                candidates.append((candidate_address, candidate))

        # Compiler version and local-entry differences can alter registers or
        # literal values while retaining the same instruction/control-flow
        # shape.  Use that looser fingerprint only when the relocation-aware
        # pass found nothing, and require at least three instructions plus a
        # single candidate inside the same owner/order span.
        if not candidates:
            relaxed_original = _instruction_shapes(original_image, entity.orig_addr, count=6)
            if relaxed_original is not None and len(relaxed_original) >= 3:
                for candidate_address in ordered_owner_boundaries.get(owner_key, ()):
                    if not search_start <= candidate_address < search_end:
                        continue
                    if candidate_address in proposed_addresses:
                        continue
                    if not _is_executable_range(recompiled_image, candidate_address, size):
                        continue
                    valid_candidate, candidate = _library_candidate_at(db, candidate_address, owner_key)
                    if not valid_candidate:
                        continue
                    if _instruction_shapes(recompiled_image, candidate_address, count=6) == relaxed_original:
                        candidates.append((candidate_address, candidate))

        # Tiny compiler thunks often move as a group and therefore fall
        # outside the immediate-anchor span. When every direct control target
        # in the original already has a verified match, use those mapped
        # targets to refine an ambiguous local fingerprint as well as to search
        # the full owning unit. This distinguishes same-shaped JMP/CALL thunks
        # without relying on their layout.
        mapped_targets = _mapped_original_control_targets(db, original_image, entity.orig_addr, size)
        if mapped_targets is not None and len(candidates) != 1:
            owner_start, owner_end = owner_range
            target_candidates: list[tuple[int, ReccmpEntity | None]] = []
            for candidate_address in ordered_owner_boundaries.get(owner_key, ()):
                if not owner_start <= candidate_address < owner_end:
                    continue
                if candidate_address in proposed_addresses:
                    continue
                if not _is_executable_range(recompiled_image, candidate_address, size):
                    continue
                valid_candidate, candidate = _library_candidate_at(db, candidate_address, owner_key)
                if not valid_candidate:
                    continue
                if _instruction_fingerprint(recompiled_image, candidate_address, size) != original_fingerprint:
                    continue
                if _direct_control_targets(recompiled_image, candidate_address, size) != mapped_targets:
                    continue
                target_candidates.append((candidate_address, candidate))
            candidates = target_candidates

        if len(candidates) != 1:
            event = ReccmpEvent.AMBIGUOUS_MATCH if len(candidates) > 1 else ReccmpEvent.GENERAL_WARNING
            report(
                event,
                entity.orig_addr,
                msg=(
                    f"Rejected Delphi fingerprint for '{spelling}': "
                    f"found {len(candidates)} candidates in owning unit"
                ),
            )
            continue

        candidate_address, candidate = candidates[0]
        proposals.append((entity, candidate_address, spelling, owner_unit, candidate))
        proposed_addresses.add(candidate_address)

    _apply_library_boundary_proposals(db, proposals, report, "unique unit-scoped instruction fingerprint")
    # A unique fingerprint can disambiguate one member of an overload group.
    # Re-run the canonical pass so a remaining one-to-one pair is not left
    # unmatched merely because the group was ambiguous before sizing/layout.
    match_delphi_library_functions(db, report)


def _lifecycle_identity(match: ReccmpMatch) -> tuple[str, str] | None:
    if not match.get("is_delphi"):
        return None

    name = match.best_name()
    if name is None or "." not in name:
        return None

    owner_unit, _, routine_name = name.rpartition(".")
    routine_key = routine_name.casefold()
    if routine_key not in ("initialization", "finalization"):
        return None

    return owner_unit, routine_key


def _absolute_dword_operand(instruction) -> int | None:
    operands = instruction.operands
    if not operands or operands[0].type != CS_OP_MEM or operands[0].size != 4:
        return None

    memory = operands[0].mem
    if memory.base != 0 or memory.index != 0:
        return None

    return memory.disp & 0xFFFFFFFF


def _is_finalization_guard_update(instruction) -> int | None:
    if instruction.mnemonic != "inc" or len(instruction.operands) != 1:
        return None

    return _absolute_dword_operand(instruction)


def _is_initialization_guard_update(instruction) -> int | None:
    if instruction.mnemonic == "dec" and len(instruction.operands) == 1:
        return _absolute_dword_operand(instruction)

    if instruction.mnemonic != "sub" or len(instruction.operands) != 2:
        return None

    immediate = instruction.operands[1]
    if immediate.type != CS_OP_IMM or immediate.imm != 1:
        return None

    return _absolute_dword_operand(instruction)


def _unique_guard_update(
    match: ReccmpMatch,
    image_id: ImageId,
    image: Image,
    predicate: Callable,
) -> tuple[int | None, str | None]:
    address = match.addr(image_id)
    if address is None:
        return None, "routine has no address"

    size = match.size(image_id) or match.max_size(image_id)
    if size is None or size <= 0:
        return None, "routine has no usable size"

    try:
        blob = image.read(address, min(size, MAX_LIFECYCLE_FUNCTION_SIZE))
    except (IndexError, ValueError, OSError):
        return None, "routine bytes are not readable"

    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    candidates: set[int] = set()
    for instruction in disassembler.disasm(blob, address):
        candidate = predicate(instruction)
        if candidate is not None:
            candidates.add(candidate)

        if instruction.mnemonic.startswith("ret"):
            break

    if len(candidates) != 1:
        return None, f"expected one guard update, found {len(candidates)}"

    return next(iter(candidates)), None


def _is_writable_data_address(image: Image, address: int) -> bool:
    sections = [
        section
        for section in image.sections
        if address in section.virtual_range and address + 3 in section.virtual_range
    ]
    if len(sections) != 1:
        return False

    flags = sections[0].flags
    return bool(flags & ImageSectionFlags.WRITE) and not bool(flags & ImageSectionFlags.EXECUTE)


def _has_guard_match_conflict(
    entity: ReccmpEntity | None,
    image_id: ImageId,
    expected_other_address: int,
) -> bool:
    if entity is None:
        return False

    if entity.get("type") not in (None, EntityType.DATA):
        return True

    if entity.orig_addr is not None and entity.recomp_addr is not None:
        other_image_id = ImageId.RECOMP if image_id == ImageId.ORIG else ImageId.ORIG
        other_address = entity.addr(other_image_id)
        return other_address != expected_other_address

    return False


def _report_skip(
    report: ReccmpReportProtocol,
    original_address: int,
    owner_unit: str,
    reason: str,
):
    report(
        ReccmpEvent.GENERAL_WARNING,
        original_address,
        msg=f"Skipped Delphi lifecycle guard for {owner_unit}: {reason}",
    )


def match_delphi_lifecycle_guards(
    db: EntityDb,
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol = reccmp_report_nop,
):  # pylint: disable=too-many-locals
    """Match unit lifecycle counters regenerated by the Delphi compiler.

    A guard is accepted only when a uniquely matched unit Initialization and
    Finalization pair updates the same absolute writable DATA DWORD on each
    image. The TD32 raw name is deliberately irrelevant to this inference.
    """

    lifecycle_functions: defaultdict[str, dict[str, list[tuple[str, ReccmpMatch]]]] = defaultdict(
        lambda: {"initialization": [], "finalization": []}
    )

    for match in db.get_functions():
        identity = _lifecycle_identity(match)
        if identity is None:
            continue

        owner_unit, routine_key = identity
        lifecycle_functions[owner_unit.casefold()][routine_key].append((owner_unit, match))

    for unit_key, routines in lifecycle_functions.items():
        initializations = routines["initialization"]
        finalizations = routines["finalization"]
        available = initializations or finalizations
        assert available
        owner_unit, representative = available[0]

        if len(initializations) != 1 or len(finalizations) != 1:
            _report_skip(
                report,
                representative.orig_addr,
                owner_unit,
                "Initialization/Finalization pair is not unique",
            )
            continue

        initialization = initializations[0][1]
        finalization = finalizations[0][1]
        if any(
            routine.get("owner_unit") is None or routine.get("owner_unit").casefold() != unit_key
            for routine in (initialization, finalization)
        ):
            _report_skip(
                report,
                finalization.orig_addr,
                owner_unit,
                "routine ownership does not agree with the qualified name",
            )
            continue

        owner_unit = finalization.get("owner_unit")
        assert isinstance(owner_unit, str)
        guards: dict[ImageId, int] = {}
        failed = False
        for image_id, image in (
            (ImageId.ORIG, original_image),
            (ImageId.RECOMP, recompiled_image),
        ):
            init_guard, init_error = _unique_guard_update(
                initialization,
                image_id,
                image,
                _is_initialization_guard_update,
            )
            final_guard, final_error = _unique_guard_update(
                finalization,
                image_id,
                image,
                _is_finalization_guard_update,
            )
            if init_error is not None or final_error is not None:
                reason = f"initialization {init_error}" if init_error is not None else f"finalization {final_error}"
                _report_skip(
                    report,
                    finalization.orig_addr,
                    owner_unit,
                    f"{image_id.name.lower()} {reason}",
                )
                failed = True
                break

            assert init_guard is not None and final_guard is not None
            if init_guard != final_guard:
                _report_skip(
                    report,
                    finalization.orig_addr,
                    owner_unit,
                    f"{image_id.name.lower()} routines update different guards",
                )
                failed = True
                break

            if not _is_writable_data_address(image, init_guard):
                _report_skip(
                    report,
                    finalization.orig_addr,
                    owner_unit,
                    f"{image_id.name.lower()} guard is not writable non-code DATA",
                )
                failed = True
                break

            guards[image_id] = init_guard

        if failed:
            continue

        original_guard = guards[ImageId.ORIG]
        recompiled_guard = guards[ImageId.RECOMP]
        original_entity = db.get(ImageId.ORIG, original_guard)
        recompiled_entity = db.get(ImageId.RECOMP, recompiled_guard)
        if _has_guard_match_conflict(original_entity, ImageId.ORIG, recompiled_guard) or _has_guard_match_conflict(
            recompiled_entity, ImageId.RECOMP, original_guard
        ):
            _report_skip(
                report,
                finalization.orig_addr,
                owner_unit,
                "guard address conflicts with an existing entity or match",
            )
            continue

        canonical_name = f"{owner_unit}.UnitFinalizationGuard"
        with db.batch() as batch:
            for image_id, address in (
                (ImageId.ORIG, original_guard),
                (ImageId.RECOMP, recompiled_guard),
            ):
                batch.set(
                    image_id,
                    address,
                    type=EntityType.DATA,
                    size=4,
                    computed_name=canonical_name,
                    owner_unit=owner_unit,
                    is_delphi=True,
                    compiler_generated=True,
                )
            batch.match(original_guard, recompiled_guard)
