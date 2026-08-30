"""Structural matching for Delphi compiler and library entities."""

# pylint: disable=too-many-lines

from collections import defaultdict
from collections.abc import Callable
from bisect import bisect_left
from dataclasses import dataclass
import re
import struct

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
MIN_LIFECYCLE_TABLE_RECORDS = 4
DELPHI_LIBRARY_ADDRESS_SUFFIX_RE = re.compile(r"_([0-9a-f]{8})$", re.IGNORECASE)
DELPHI_LIBRARY_SIGNATURE_SUFFIX_RE = re.compile(r"\((?!\d+\)$)[^()]+\)$")
DELPHI_LIFECYCLE_NAME_RE = re.compile(
    r"(?:^|\.)(initialization|finalization)(?:_[0-9a-f]{8}|\(\d+\))?$",
    re.IGNORECASE,
)
ANONYMOUS_DELPHI_UNIT_RE = re.compile(r"^unit\d+$", re.IGNORECASE)
DELPHI_COMPILER_STARTUP_ROUTINES = frozenset(
    {
        "alloctlsbuffer",
        "gettlssize",
        "initthreadtls",
        "gettls",
        "initializemodule",
        "initexe",
    }
)


def _original_address(entity: ReccmpEntity) -> int:
    address = entity.orig_addr
    assert address is not None
    return address


def _recompiled_address(entity: ReccmpEntity) -> int:
    address = entity.recomp_addr
    assert address is not None
    return address


def _anonymous_delphi_unit_key(name: str) -> int | None:
    if ANONYMOUS_DELPHI_UNIT_RE.fullmatch(name) is None:
        return None
    return int(name[4:])


def _anonymous_delphi_unit_aliases(db: EntityDb) -> dict[int, str]:
    """Return source owners proven by already matched anonymous lifecycles."""

    candidates: defaultdict[int, set[str]] = defaultdict(set)
    for entity in db.all(ImageId.ORIG):
        raw_name = entity.name
        best_name = entity.best_name()
        if (  # pylint: disable=too-many-boolean-expressions
            not entity.matched
            or not isinstance(raw_name, str)
            or not isinstance(best_name, str)
            or "." not in raw_name
            or "." not in best_name
            or _lifecycle_routine_key(entity) is None
        ):
            continue
        raw_owner = raw_name.split(".", 1)[0]
        key = _anonymous_delphi_unit_key(raw_owner)
        best_owner = best_name.split(".", 1)[0]
        if key is not None and _anonymous_delphi_unit_key(best_owner) is None:
            candidates[key].add(best_owner)
    return {
        key: next(iter(owners))
        for key, owners in candidates.items()
        if len(owners) == 1
    }


def _canonical_original_library_name(
    entity: ReccmpEntity,
    anonymous_unit_aliases: dict[int, str] | None = None,
) -> str | None:
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

    # Runtime inventories sometimes distinguish Delphi overloads with a
    # reporting-only parameter type. TD32 stores the shared routine name; put
    # only non-numeric signature suffixes into the overload group and let the
    # existing unique-size rule select a member.
    name = DELPHI_LIBRARY_SIGNATURE_SUFFIX_RE.sub("", name)

    parts = name.split(".")
    if anonymous_unit_aliases and parts:
        unit_key = _anonymous_delphi_unit_key(parts[0])
        if unit_key in anonymous_unit_aliases:
            parts[0] = anonymous_unit_aliases[unit_key]
        name = ".".join(parts)

    # Delphi identifiers are case-insensitive.  TD32 also omits IDR's ``@``
    # compiler decoration from individual qualified-name components.
    name = ".".join(part.removeprefix("@") for part in name.split("."))
    return name.rstrip(".").casefold()


def _canonical_recompiled_library_name(entity: ReccmpEntity) -> str | None:
    name = entity.name
    owner_unit = entity.get("owner_unit")
    if (
        not entity.get("is_delphi")
        or not isinstance(name, str)
        or not isinstance(owner_unit, str)
    ):
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

    anonymous_unit_aliases = _anonymous_delphi_unit_aliases(db)
    original_groups: defaultdict[str, list[ReccmpEntity]] = defaultdict(list)
    recompiled_groups: defaultdict[str, list[ReccmpEntity]] = defaultdict(list)

    for entity in db.unmatched(ImageId.ORIG):
        if entity.entity_type != EntityType.FUNCTION or not entity.get("library"):
            continue
        key = _canonical_original_library_name(entity, anonymous_unit_aliases)
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
    _match_delphi_library_overload_order(db, report)
    _match_delphi_nested_library_functions(db, report)


def _matched_delphi_library_anchors(db: EntityDb, owner_key: str) -> list[ReccmpMatch]:
    return [
        match
        for match in db.get_functions()
        if match.get("library")
        and match.get("is_delphi")
        and isinstance(match.get("owner_unit"), str)
        and match.get("owner_unit").casefold() == owner_key
    ]


def _match_delphi_library_overload_order(
    db: EntityDb,
    report: ReccmpReportProtocol,
) -> None:
    """Resolve equal overload groups only inside corresponding matched anchors."""

    aliases = _anonymous_delphi_unit_aliases(db)
    original_groups: defaultdict[str, list[ReccmpEntity]] = defaultdict(list)
    recompiled_groups: defaultdict[str, list[ReccmpEntity]] = defaultdict(list)
    for entity in db.unmatched(ImageId.ORIG):
        if entity.entity_type == EntityType.FUNCTION and entity.get("library"):
            key = _canonical_original_library_name(entity, aliases)
            if key is not None:
                original_groups[key].append(entity)
    for entity in db.unmatched(ImageId.RECOMP):
        if entity.entity_type == EntityType.FUNCTION:
            key = _canonical_recompiled_library_name(entity)
            if key is not None:
                recompiled_groups[key].append(entity)

    pairs: list[tuple[int, int]] = []
    for key, originals in original_groups.items():
        candidates = recompiled_groups.get(key, [])
        if len(originals) != len(candidates) or len(originals) < 2:
            continue
        originals.sort(key=_original_address)
        candidates.sort(key=_recompiled_address)
        first_original_address = _original_address(originals[0])
        last_original_address = _original_address(originals[-1])
        first_recompiled_address = _recompiled_address(candidates[0])
        last_recompiled_address = _recompiled_address(candidates[-1])
        owner_key = key.split(".", 1)[0]
        anchors = _matched_delphi_library_anchors(db, owner_key)

        def position(address: int, first: int, last: int) -> int:
            if address < first:
                return -1
            if address > last:
                return 1
            return 0

        if any(
            position(anchor.orig_addr, first_original_address, last_original_address)
            != position(
                anchor.recomp_addr,
                first_recompiled_address,
                last_recompiled_address,
            )
            for anchor in anchors
        ):
            continue
        original_before = [
            anchor for anchor in anchors if anchor.orig_addr < first_original_address
        ]
        original_after = [
            anchor for anchor in anchors if anchor.orig_addr > last_original_address
        ]
        recompiled_before = [
            anchor
            for anchor in anchors
            if anchor.recomp_addr < first_recompiled_address
        ]
        recompiled_after = [
            anchor for anchor in anchors if anchor.recomp_addr > last_recompiled_address
        ]
        if not all(
            (original_before, original_after, recompiled_before, recompiled_after)
        ):
            continue
        if max(original_before, key=lambda anchor: anchor.orig_addr) is not max(
            recompiled_before, key=lambda anchor: anchor.recomp_addr
        ) or min(original_after, key=lambda anchor: anchor.orig_addr) is not min(
            recompiled_after, key=lambda anchor: anchor.recomp_addr
        ):
            continue

        for original, candidate in zip(originals, candidates):
            assert original.orig_addr is not None and candidate.recomp_addr is not None
            pairs.append((original.orig_addr, candidate.recomp_addr))
        report(
            ReccmpEvent.GENERAL_WARNING,
            first_original_address,
            msg=f"Matched Delphi overload group '{key}' by verified anchored source order",
        )
    db.bulk_match(pairs)


def _match_delphi_nested_library_functions(
    db: EntityDb,
    report: ReccmpReportProtocol,
) -> None:
    """Match a unique TD32-flattened nested routine to its source hierarchy."""

    aliases = _anonymous_delphi_unit_aliases(db)
    known_original_names = {
        key
        for entity in db.all(ImageId.ORIG)
        if entity.entity_type == EntityType.FUNCTION
        for key in [_canonical_original_library_name(entity, aliases)]
        if key is not None
    }
    recompiled_by_flat_name: defaultdict[str, list[ReccmpEntity]] = defaultdict(list)
    for entity in db.unmatched(ImageId.RECOMP):
        if entity.entity_type != EntityType.FUNCTION:
            continue
        key = _canonical_recompiled_library_name(entity)
        if key is not None:
            recompiled_by_flat_name[key].append(entity)

    pairs: list[tuple[int, int]] = []
    for entity in db.unmatched(ImageId.ORIG):
        if entity.entity_type != EntityType.FUNCTION or not entity.get("library"):
            continue
        key = _canonical_original_library_name(entity, aliases)
        if key is None:
            continue
        parts = key.split(".")
        if len(parts) < 3 or ".".join(parts[:-1]) not in known_original_names:
            continue
        flat_key = f"{parts[0]}.{parts[-1]}"
        candidates = recompiled_by_flat_name.get(flat_key, [])
        if len(candidates) != 1:
            if candidates:
                assert entity.orig_addr is not None
                report(
                    ReccmpEvent.AMBIGUOUS_MATCH,
                    entity.orig_addr,
                    msg=f"Ambiguous flattened Delphi nested routine '{flat_key}'",
                )
            continue
        assert entity.orig_addr is not None and candidates[0].recomp_addr is not None
        pairs.append((entity.orig_addr, candidates[0].recomp_addr))
    db.bulk_match(pairs)


def match_delphi_compiler_startup_functions(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
) -> None:
    """Associate Delphi's anonymous executable startup unit with SysInit."""

    originals: dict[str, list[ReccmpEntity]] = defaultdict(list)
    candidates: dict[str, list[ReccmpEntity]] = defaultdict(list)
    for entity in db.unmatched(ImageId.ORIG):
        name = entity.name
        if (
            entity.entity_type != EntityType.FUNCTION
            or not entity.get("library")
            or not isinstance(name, str)
        ):
            continue
        parts = [part.removeprefix("@").casefold() for part in name.split(".")]
        if (
            len(parts) == 2
            and _anonymous_delphi_unit_key(parts[0]) is not None
            and parts[1] in DELPHI_COMPILER_STARTUP_ROUTINES
        ):
            originals[parts[1]].append(entity)
    for entity in db.unmatched(ImageId.RECOMP):
        name = entity.name
        owner = entity.get("owner_unit")
        if (
            entity.entity_type != EntityType.FUNCTION
            or not entity.get("is_delphi")
            or not isinstance(name, str)
            or not isinstance(owner, str)
            or owner.casefold() != "sysinit"
        ):
            continue
        leaf = name.rsplit(".", 1)[-1].removeprefix("@").casefold()
        if leaf in DELPHI_COMPILER_STARTUP_ROUTINES:
            candidates[leaf].append(entity)

    shared = set(originals) & set(candidates)
    if len(shared) < 3:
        return
    pairs: list[tuple[int, int]] = []
    for leaf in shared:
        if len(originals[leaf]) != 1 or len(candidates[leaf]) != 1:
            continue
        original = originals[leaf][0]
        candidate = candidates[leaf][0]
        if original.size(ImageId.ORIG) != candidate.size(ImageId.RECOMP):
            continue
        assert original.orig_addr is not None and candidate.recomp_addr is not None
        pairs.append((original.orig_addr, candidate.recomp_addr))
    if len(pairs) < 3:
        return
    db.bulk_match(pairs)
    report(
        ReccmpEvent.GENERAL_WARNING,
        min(original for original, _ in pairs),
        msg=f"Matched {len(pairs)} Delphi SysInit startup routines by name and exact size",
    )


def _canonical_original_library_spelling(
    entity: ReccmpEntity,
    anonymous_unit_aliases: dict[int, str] | None = None,
) -> str | None:
    name = entity.name
    if not isinstance(name, str) or entity.orig_addr is None:
        return None

    suffix = DELPHI_LIBRARY_ADDRESS_SUFFIX_RE.search(name)
    if suffix is not None:
        if int(suffix.group(1), 16) != entity.orig_addr:
            return None
        name = name[: suffix.start()]

    parts = [part.removeprefix("@") for part in name.split(".")]
    if anonymous_unit_aliases and parts:
        unit_key = _anonymous_delphi_unit_key(parts[0])
        if unit_key in anonymous_unit_aliases:
            parts[0] = anonymous_unit_aliases[unit_key]
    return ".".join(parts).rstrip(".")


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
                tuple(
                    _instruction_operand_shape(instruction, operand)
                    for operand in instruction.operands
                ),
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
        if (
            memory.base == 0
            and memory.index == 0
            and _is_relocated_operand(image, relocation_site)
        ):
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


def _instruction_fingerprint(
    image: Image, address: int, size: int, count: int = 8
) -> tuple | None:
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
                    _instruction_fingerprint_operand(image, instruction, operand)
                    for operand in instruction.operands
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


def _first_direct_local_jump_target(
    image: Image, address: int, size: int
) -> int | None:
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


def _direct_control_targets(
    image: Image, address: int, size: int
) -> tuple[tuple[str, int], ...]:
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


def _library_candidate_at(
    db: EntityDb, address: int, owner_key: str
) -> tuple[bool, ReccmpEntity | None]:
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
        (containing.size(ImageId.RECOMP) or containing.max_size(ImageId.RECOMP) or 0)
        if containing is not None
        else 0
    )
    valid = (
        containing is not None
        and containing.recomp_addr is not None
        and containing.recomp_addr < address <= containing.recomp_addr + containing_size
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
            inferred_size = (
                entity.size(ImageId.ORIG) or entity.max_size(ImageId.ORIG) or 0
            )
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
            previous_owner = (
                previous.get("owner_unit") if previous is not None else None
            )
            if (  # pylint: disable=too-many-boolean-expressions
                previous is not None
                and previous.recomp_addr is not None
                and previous.recomp_addr < recompiled_address
                and isinstance(previous_owner, str)
                and previous_owner.casefold() == owner_unit.casefold()
                and (previous.size(ImageId.RECOMP) or 0)
                > recompiled_address - previous.recomp_addr
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
            msg=(
                f"Matched Delphi library boundary '{spelling}' at "
                f"0x{recompiled_address:x} from {reason}"
            ),
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

    anonymous_unit_aliases = _anonymous_delphi_unit_aliases(db)
    anchors_by_owner: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
    for match in db.get_functions():
        owner_unit = match.get("owner_unit")
        if (
            match.get("library")
            and match.get("is_delphi")
            and isinstance(owner_unit, str)
        ):
            anchors_by_owner[owner_unit.casefold()].append(
                (match.orig_addr, match.recomp_addr)
            )
    for anchors in anchors_by_owner.values():
        anchors.sort()

    proposals: list[LibraryBoundaryProposal] = []
    proposed_recompiled_addresses: set[int] = set()

    for entity in db.unmatched(ImageId.ORIG):
        if entity.entity_type != EntityType.FUNCTION or not entity.get("library"):
            continue

        spelling = _canonical_original_library_spelling(entity, anonymous_unit_aliases)
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
        if not _is_executable_range(
            recompiled_image, recompiled_address, inferred_size
        ):
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
    _match_delphi_library_alternate_entries(
        db, original_image, recompiled_image, report
    )
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
                if 0 < boundary_size < size:
                    batch.set(image_id, address, size=boundary_size)


def _is_writable_data_range(image: Image, address: int, size: int) -> bool:
    """Return whether one complete range belongs to writable, non-code storage."""

    if size <= 0:
        return False
    sections = [
        section
        for section in image.sections
        if address in section.virtual_range
        and address + size - 1 in section.virtual_range
    ]
    if len(sections) != 1:
        return False
    flags = sections[0].flags
    return bool(flags & ImageSectionFlags.WRITE) and not bool(
        flags & ImageSectionFlags.EXECUTE
    )


def _data_match_candidate_is_available(
    db: EntityDb, recompiled_address: int, original_address: int
) -> bool:
    """Reject a rebuilt DATA target already claimed by another entity."""

    candidate = db.get(ImageId.RECOMP, recompiled_address, exact=True)
    if candidate is None:
        return True
    if candidate.entity_type not in (None, EntityType.DATA):
        return False
    if not candidate.matched:
        return True
    return candidate.orig_addr == original_address


def match_delphi_library_data_references(
    db: EntityDb,
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    """Match private Delphi DATA through corresponding relocated references.

    Stock Delphi units contain resourcestring cells, linker aliases, and local
    constant tables that have no public TD32 symbol.  Their identity is still
    present in the binaries: corresponding instructions in an already matched
    stock-library function have PE relocations at the same relative byte and
    refer to the corresponding DATA cell.  Accept a pair only when every such
    stock reference agrees and the inferred relation is one-to-one.

    Application functions are intentionally excluded.  A source-level change
    there could place a different relocation at the same byte offset; stock
    library functions provide the independent, fixed-code anchor needed for
    this structural inference.
    """

    original_relocations = tuple(sorted(getattr(original_image, "relocations", ())))
    recompiled_relocations = frozenset(getattr(recompiled_image, "relocations", ()))
    if not original_relocations or not recompiled_relocations:
        return

    proposals: defaultdict[int, set[int]] = defaultdict(set)
    evidence_counts: defaultdict[tuple[int, int], int] = defaultdict(int)
    for function in db.get_functions():
        if not function.get("library") or not function.get("is_delphi"):
            continue

        original_size = function.size(ImageId.ORIG) or function.max_size(ImageId.ORIG)
        recompiled_size = function.size(ImageId.RECOMP) or function.max_size(
            ImageId.RECOMP
        )
        if not original_size or not recompiled_size:
            continue
        shared_size = min(original_size, recompiled_size)

        first = bisect_left(original_relocations, function.orig_addr)
        last = bisect_left(
            original_relocations, function.orig_addr + shared_size, lo=first
        )
        for original_site in original_relocations[first:last]:
            relative_site = original_site - function.orig_addr
            recompiled_site = function.recomp_addr + relative_site
            if recompiled_site not in recompiled_relocations:
                continue

            try:
                (original_target,) = struct.unpack(
                    "<L", original_image.read(original_site, 4)
                )
                (recompiled_target,) = struct.unpack(
                    "<L", recompiled_image.read(recompiled_site, 4)
                )
            except (IndexError, ValueError, OSError, struct.error):
                continue

            original_entity = db.get(ImageId.ORIG, original_target, exact=True)
            if (
                original_entity is None
                or original_entity.matched
                or original_entity.entity_type != EntityType.DATA
            ):
                continue
            size = original_entity.size(ImageId.ORIG)
            if (
                size is None
                or not _is_writable_data_range(original_image, original_target, size)
                or not _is_writable_data_range(
                    recompiled_image, recompiled_target, size
                )
                or not _data_match_candidate_is_available(
                    db, recompiled_target, original_target
                )
            ):
                continue

            proposals[original_target].add(recompiled_target)
            evidence_counts[(original_target, recompiled_target)] += 1

    reverse_proposals: defaultdict[int, set[int]] = defaultdict(set)
    for original_address, candidates in proposals.items():
        if len(candidates) == 1:
            reverse_proposals[next(iter(candidates))].add(original_address)

    accepted: list[tuple[ReccmpEntity, int]] = []
    for original_address, candidates in proposals.items():
        original_entity = db.get(ImageId.ORIG, original_address, exact=True)
        assert original_entity is not None
        if len(candidates) != 1:
            report(
                ReccmpEvent.AMBIGUOUS_MATCH,
                original_address,
                msg=(
                    f"Rejected Delphi library DATA '{original_entity.best_name()}': "
                    f"relocated references proposed {len(candidates)} rebuilt targets"
                ),
            )
            continue

        recompiled_address = next(iter(candidates))
        if len(reverse_proposals[recompiled_address]) != 1:
            report(
                ReccmpEvent.AMBIGUOUS_MATCH,
                original_address,
                msg=(
                    f"Rejected Delphi library DATA '{original_entity.best_name()}': "
                    "rebuilt target is not one-to-one"
                ),
            )
            continue
        accepted.append((original_entity, recompiled_address))

    with db.batch() as batch:
        for original_entity, recompiled_address in accepted:
            original_address = _original_address(original_entity)
            size = original_entity.size(ImageId.ORIG)
            name = original_entity.best_name()
            assert size is not None and name is not None
            batch.set(
                ImageId.ORIG,
                original_address,
                library=True,
                is_delphi=True,
                data_match_reason="relocated_library_reference",
                data_match_evidence=evidence_counts[
                    (original_address, recompiled_address)
                ],
            )
            batch.set(
                ImageId.RECOMP,
                recompiled_address,
                type=EntityType.DATA,
                size=size,
                computed_name=name,
                library=True,
                is_delphi=True,
                data_match_reason="relocated_library_reference",
            )
            batch.match(original_address, recompiled_address)


def _match_delphi_library_alternate_entries(
    db: EntityDb,
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol,
):
    """Map hidden entries reached by a matched parent's local jump."""

    anonymous_unit_aliases = _anonymous_delphi_unit_aliases(db)
    anchors_by_owner: defaultdict[str, list[ReccmpMatch]] = defaultdict(list)
    for match in db.get_functions():
        owner_unit = match.get("owner_unit")
        if (
            match.get("library")
            and match.get("is_delphi")
            and isinstance(owner_unit, str)
        ):
            anchors_by_owner[owner_unit.casefold()].append(match)
    for anchors in anchors_by_owner.values():
        anchors.sort(key=lambda item: item.orig_addr)

    proposals: list[LibraryBoundaryProposal] = []
    proposed_addresses: set[int] = set()
    for entity in list(db.unmatched(ImageId.ORIG)):
        spelling = _canonical_original_library_spelling(entity, anonymous_unit_aliases)
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
            (
                anchor
                for anchor in reversed(anchors)
                if anchor.orig_addr < entity.orig_addr
            ),
            None,
        )
        if previous is None:
            continue

        original_parent_size = (
            previous.max_size(ImageId.ORIG) or previous.size(ImageId.ORIG) or 0
        )
        original_first_target = _first_direct_local_jump_target(
            original_image, previous.orig_addr, original_parent_size
        )
        if (
            entity.orig_addr != original_first_target
            and entity.orig_addr
            not in _direct_local_jump_targets(
                original_image, previous.orig_addr, original_parent_size
            )
        ):
            continue

        recompiled_parent_size = (
            previous.size(ImageId.RECOMP) or previous.max_size(ImageId.RECOMP) or 0
        )
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
            candidates = _direct_local_jump_targets(
                recompiled_image, previous.recomp_addr, recompiled_parent_size
            )
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
                        f"Rejected Delphi alternate entry '{spelling}': "
                        f"found {len(candidates)} local jump targets"
                    ),
                )
            continue

        address = next(iter(candidates))
        _, candidate = _library_candidate_at(db, address, owner_key)
        proposals.append((entity, address, spelling, owner_unit, candidate))
        proposed_addresses.add(address)

    _apply_library_boundary_proposals(
        db, proposals, report, "matched-parent local control flow"
    )


def _match_delphi_library_fingerprints(
    db: EntityDb,
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol,
):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Find layout-break boundaries by unique, unit-scoped code shape."""

    anonymous_unit_aliases = _anonymous_delphi_unit_aliases(db)
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
        end = entity.recomp_addr + (
            entity.size(ImageId.RECOMP) or entity.max_size(ImageId.RECOMP) or 1
        )
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
            instruction.address
            for instruction in boundary_disassembler.disasm(blob, entity.recomp_addr)
        )

    ordered_owner_boundaries = {
        owner: tuple(sorted(addresses))
        for owner, addresses in owner_instruction_boundaries.items()
    }

    for match in db.get_functions():
        owner_unit = match.get("owner_unit")
        if (
            match.get("library")
            and match.get("is_delphi")
            and isinstance(owner_unit, str)
        ):
            anchors_by_owner[owner_unit.casefold()].append(
                (match.orig_addr, match.recomp_addr)
            )
    for anchors in anchors_by_owner.values():
        anchors.sort()

    proposals: list[LibraryBoundaryProposal] = []
    proposed_addresses: set[int] = set()
    for entity in list(db.unmatched(ImageId.ORIG)):
        if entity.entity_type != EntityType.FUNCTION or not entity.get("library"):
            continue
        spelling = _canonical_original_library_spelling(entity, anonymous_unit_aliases)
        if spelling is None or "." not in spelling or entity.orig_addr is None:
            continue
        owner_unit = spelling.split(".", 1)[0]
        owner_key = owner_unit.casefold()
        owner_range = owner_ranges.get(owner_key)
        if owner_range is None:
            continue

        size = entity.size(ImageId.ORIG) or entity.max_size(ImageId.ORIG) or 0
        original_fingerprint = _instruction_fingerprint(
            original_image, entity.orig_addr, size
        )
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

            valid_candidate, candidate = _library_candidate_at(
                db, candidate_address, owner_key
            )
            if not valid_candidate:
                continue

            if (
                _instruction_fingerprint(recompiled_image, candidate_address, size)
                == original_fingerprint
            ):
                candidates.append((candidate_address, candidate))

        # Compiler version and local-entry differences can alter registers or
        # literal values while retaining the same instruction/control-flow
        # shape.  Use that looser fingerprint only when the relocation-aware
        # pass found nothing, and require at least three instructions plus a
        # single candidate inside the same owner/order span.
        if not candidates:
            relaxed_original = _instruction_shapes(
                original_image, entity.orig_addr, count=6
            )
            if relaxed_original is not None and len(relaxed_original) >= 3:
                for candidate_address in ordered_owner_boundaries.get(owner_key, ()):
                    if not search_start <= candidate_address < search_end:
                        continue
                    if candidate_address in proposed_addresses:
                        continue
                    if not _is_executable_range(
                        recompiled_image, candidate_address, size
                    ):
                        continue
                    valid_candidate, candidate = _library_candidate_at(
                        db, candidate_address, owner_key
                    )
                    if not valid_candidate:
                        continue
                    if (
                        _instruction_shapes(
                            recompiled_image, candidate_address, count=6
                        )
                        == relaxed_original
                    ):
                        candidates.append((candidate_address, candidate))

        # Tiny compiler thunks often move as a group and therefore fall
        # outside the immediate-anchor span. When every direct control target
        # in the original already has a verified match, use those mapped
        # targets to refine an ambiguous local fingerprint as well as to search
        # the full owning unit. This distinguishes same-shaped JMP/CALL thunks
        # without relying on their layout.
        mapped_targets = _mapped_original_control_targets(
            db, original_image, entity.orig_addr, size
        )
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
                valid_candidate, candidate = _library_candidate_at(
                    db, candidate_address, owner_key
                )
                if not valid_candidate:
                    continue
                if (
                    _instruction_fingerprint(recompiled_image, candidate_address, size)
                    != original_fingerprint
                ):
                    continue
                if (
                    _direct_control_targets(recompiled_image, candidate_address, size)
                    != mapped_targets
                ):
                    continue
                target_candidates.append((candidate_address, candidate))
            candidates = target_candidates

        if len(candidates) != 1:
            event = (
                ReccmpEvent.AMBIGUOUS_MATCH
                if len(candidates) > 1
                else ReccmpEvent.GENERAL_WARNING
            )
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

    _apply_library_boundary_proposals(
        db, proposals, report, "unique unit-scoped instruction fingerprint"
    )
    # A unique fingerprint can disambiguate one member of an overload group.
    # Re-run the canonical pass so a remaining one-to-one pair is not left
    # unmatched merely because the group was ambiguous before sizing/layout.
    match_delphi_library_functions(db, report)


@dataclass(frozen=True)
class _LifecycleTableRecord:
    table_address: int
    initialization_address: int
    finalization_address: int
    initialization: ReccmpEntity | None
    finalization: ReccmpEntity | None


def _lifecycle_routine_key(entity: ReccmpEntity | None) -> str | None:
    if entity is None:
        return None
    name = entity.best_name()
    if not isinstance(name, str):
        return None
    match = DELPHI_LIFECYCLE_NAME_RE.search(name)
    return match.group(1).casefold() if match is not None else None


def _lifecycle_original_owner(entity: ReccmpEntity | None) -> str | None:
    if entity is None:
        return None
    name = entity.best_name()
    if not isinstance(name, str) or "." not in name:
        return None
    return name.split(".", 1)[0]


def _lifecycle_entities_by_address(
    db: EntityDb, image_id: ImageId
) -> dict[int, ReccmpEntity]:
    result: dict[int, ReccmpEntity] = {}
    for entity in db.all(image_id):
        address = entity.addr(image_id)
        if (
            address is not None
            and entity.entity_type == EntityType.FUNCTION
            and _lifecycle_routine_key(entity) is not None
        ):
            result[address] = entity
    return result


def _find_delphi_lifecycle_table(
    db: EntityDb,
    image_id: ImageId,
    image: Image,
) -> tuple[_LifecycleTableRecord, ...] | None:
    """Find the unique longest Delphi unit initialization table.

    Delphi emits the table as pairs of absolute function pointers in
    ``Initialization, Finalization`` order.  A null pointer is allowed for one
    half of a record, but every accepted record must expose at least one known
    lifecycle routine.  The real table is by far the longest such run in a PE;
    reject equal longest runs rather than choosing one by address.
    """

    lifecycle = _lifecycle_entities_by_address(db, image_id)
    candidates: list[tuple[_LifecycleTableRecord, ...]] = []

    def is_executable_pointer(address: int) -> bool:
        if address == 0:
            return True
        return any(
            address in section.virtual_range
            and section.flags & ImageSectionFlags.EXECUTE
            for section in image.sections
        )

    for section in image.sections:
        if not section.flags & ImageSectionFlags.READ:
            continue
        data = section.view
        aligned_start = (-section.virtual_range.start) % 4
        for offset in range(aligned_start, len(data) - 7, 4):
            initialization_address, finalization_address = struct.unpack_from(
                "<II", data, offset
            )
            initialization = lifecycle.get(initialization_address)
            finalization = lifecycle.get(finalization_address)
            if _lifecycle_routine_key(initialization) != "initialization":
                continue
            if finalization_address != 0 and (
                _lifecycle_routine_key(finalization) != "finalization"
            ):
                continue

            records: list[_LifecycleTableRecord] = []
            cursor = offset
            while cursor <= len(data) - 8:
                initialization_address, finalization_address = struct.unpack_from(
                    "<II", data, cursor
                )
                initialization = lifecycle.get(initialization_address)
                finalization = lifecycle.get(finalization_address)
                initialization_key = _lifecycle_routine_key(initialization)
                finalization_key = _lifecycle_routine_key(finalization)
                if initialization_key not in (None, "initialization"):
                    break
                if finalization_key not in (None, "finalization"):
                    break
                if initialization_address == 0 and finalization_address == 0:
                    break
                known_keys = {initialization_key, finalization_key} - {None}
                if (
                    not known_keys
                    or not is_executable_pointer(initialization_address)
                    or not is_executable_pointer(finalization_address)
                ):
                    break
                records.append(
                    _LifecycleTableRecord(
                        table_address=section.virtual_range.start + cursor,
                        initialization_address=initialization_address,
                        finalization_address=finalization_address,
                        initialization=initialization,
                        finalization=finalization,
                    )
                )
                cursor += 8

            if len(records) >= MIN_LIFECYCLE_TABLE_RECORDS:
                candidates.append(tuple(records))

    if not candidates:
        return None
    longest_size = max(len(candidate) for candidate in candidates)
    longest = [candidate for candidate in candidates if len(candidate) == longest_size]
    return longest[0] if len(longest) == 1 else None


def _lifecycle_record_owner(record: _LifecycleTableRecord) -> str | None:
    owners = {
        entity.get("owner_unit")
        for entity in (record.initialization, record.finalization)
        if entity is not None and isinstance(entity.get("owner_unit"), str)
    }
    return next(iter(owners)) if len(owners) == 1 else None


def _lifecycle_record_match_index(
    record: _LifecycleTableRecord,
    recompiled_record_by_function: dict[int, int],
) -> int | None:
    indices = {
        recompiled_record_by_function[entity.recomp_addr]
        for entity in (record.initialization, record.finalization)
        if entity is not None
        and entity.matched
        and entity.recomp_addr in recompiled_record_by_function
    }
    return next(iter(indices)) if len(indices) == 1 else None


# pylint: disable-next=too-many-return-statements
def _lifecycle_record_proposals(
    original: _LifecycleTableRecord,
    recompiled: _LifecycleTableRecord,
) -> list[tuple[ReccmpEntity, ReccmpEntity, str]] | None:
    """Validate a table-record association and return its unmatched pairs."""

    owner_unit = _lifecycle_record_owner(recompiled)
    if owner_unit is None:
        return None

    proposals: list[tuple[ReccmpEntity, ReccmpEntity, str]] = []
    for routine_key, original_entity, recompiled_entity in (
        ("initialization", original.initialization, recompiled.initialization),
        ("finalization", original.finalization, recompiled.finalization),
    ):
        if (original_entity is None) != (recompiled_entity is None):
            return None
        if original_entity is None or recompiled_entity is None:
            continue
        if (
            _lifecycle_routine_key(original_entity) != routine_key
            or _lifecycle_routine_key(recompiled_entity) != routine_key
        ):
            return None
        if original_entity.matched:
            if original_entity.recomp_addr != recompiled_entity.recomp_addr:
                return None
            continue
        if recompiled_entity.matched:
            return None
        original_owner = _lifecycle_original_owner(original_entity)
        if (  # pylint: disable=too-many-boolean-expressions
            not original_entity.get("library")
            or not isinstance(original_owner, str)
            or ANONYMOUS_DELPHI_UNIT_RE.fullmatch(original_owner) is None
            or not recompiled_entity.get("is_delphi")
            or not isinstance(recompiled_entity.get("owner_unit"), str)
            or recompiled_entity.get("owner_unit").casefold() != owner_unit.casefold()
        ):
            return None
        canonical_routine = routine_key.title()
        proposals.append(
            (
                original_entity,
                recompiled_entity,
                f"{owner_unit}.{canonical_routine}",
            )
        )

    return proposals


def _commit_lifecycle_function_proposals(
    db: EntityDb,
    proposals: list[tuple[ReccmpEntity, ReccmpEntity, str]],
    report: ReccmpReportProtocol,
    reason: str,
) -> None:
    with db.batch() as batch:
        for original_entity, recompiled_entity, canonical_name in proposals:
            assert original_entity.orig_addr is not None
            assert recompiled_entity.recomp_addr is not None
            batch.set(
                ImageId.ORIG,
                original_entity.orig_addr,
                computed_name=canonical_name,
                compiler_generated=True,
            )
            batch.match(original_entity.orig_addr, recompiled_entity.recomp_addr)

    for original_entity, recompiled_entity, canonical_name in proposals:
        assert original_entity.orig_addr is not None
        assert recompiled_entity.recomp_addr is not None
        report(
            ReccmpEvent.GENERAL_WARNING,
            original_entity.orig_addr,
            msg=(
                f"Matched Delphi lifecycle function '{canonical_name}' at "
                f"0x{recompiled_entity.recomp_addr:x} from {reason}"
            ),
        )


# pylint: disable-next=too-many-positional-arguments
def _match_delphi_lifecycle_code_boundaries(
    db: EntityDb,
    original_table: tuple[_LifecycleTableRecord, ...],
    recompiled_table: tuple[_LifecycleTableRecord, ...],
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol,
) -> None:
    """Match the first anonymous lifecycle record after a proven unit body."""

    non_lifecycle_matches = sorted(
        (
            match
            for match in db.get_functions()
            if _lifecycle_routine_key(match) is None
            and isinstance(match.get("owner_unit"), str)
        ),
        key=lambda match: match.orig_addr,
    )
    if not non_lifecycle_matches:
        return
    match_addresses = [match.orig_addr for match in non_lifecycle_matches]

    recompiled_records_by_owner: defaultdict[str, list[_LifecycleTableRecord]] = (
        defaultdict(list)
    )
    for record in recompiled_table:
        owner_unit = _lifecycle_record_owner(record)
        if owner_unit is not None:
            recompiled_records_by_owner[owner_unit.casefold()].append(record)

    original_records_by_gap: defaultdict[
        tuple[int, int | None], list[tuple[int, _LifecycleTableRecord]]
    ] = defaultdict(list)
    for record in original_table:
        entities = [
            entity
            for entity in (record.initialization, record.finalization)
            if entity is not None
        ]
        if not entities or any(entity.matched for entity in entities):
            continue
        owners = {_lifecycle_original_owner(entity) for entity in entities}
        if len(owners) != 1:
            continue
        original_owner = next(iter(owners))
        if (
            not isinstance(original_owner, str)
            or ANONYMOUS_DELPHI_UNIT_RE.fullmatch(original_owner) is None
        ):
            continue
        code_start = min(
            entity.orig_addr for entity in entities if entity.orig_addr is not None
        )
        code_end = max(
            entity.orig_addr for entity in entities if entity.orig_addr is not None
        )
        insertion_index = bisect_left(match_addresses, code_start)
        if insertion_index == 0:
            continue
        previous = non_lifecycle_matches[insertion_index - 1]
        next_address = (
            non_lifecycle_matches[insertion_index].orig_addr
            if insertion_index < len(non_lifecycle_matches)
            else None
        )
        if next_address is not None and code_end >= next_address:
            continue
        original_records_by_gap[(previous.orig_addr, next_address)].append(
            (code_start, record)
        )

    proposals: list[tuple[ReccmpEntity, ReccmpEntity, str]] = []
    for (previous_address, _), records in original_records_by_gap.items():
        # Only the first lifecycle record can belong to the preceding unit.
        _, original_record = min(records, key=lambda item: item[0])
        previous_entity = db.get(ImageId.ORIG, previous_address)
        owner_unit = (
            previous_entity.get("owner_unit") if previous_entity is not None else None
        )
        if not isinstance(owner_unit, str):
            continue
        candidates = recompiled_records_by_owner.get(owner_unit.casefold(), [])
        if len(candidates) != 1:
            continue
        record_proposals = _lifecycle_record_proposals(original_record, candidates[0])
        if record_proposals is None:
            continue
        if any(
            not _is_executable_range(
                original_image,
                _original_address(original_entity),
                original_entity.size(ImageId.ORIG)
                or original_entity.max_size(ImageId.ORIG)
                or 0,
            )
            or not _is_executable_range(
                recompiled_image,
                _recompiled_address(recompiled_entity),
                recompiled_entity.size(ImageId.RECOMP)
                or recompiled_entity.max_size(ImageId.RECOMP)
                or 0,
            )
            for original_entity, recompiled_entity, _ in record_proposals
        ):
            continue
        proposals.extend(record_proposals)

    _commit_lifecycle_function_proposals(
        db, proposals, report, "verified owning-unit code boundary"
    )


def _lifecycle_record_guard(
    record: _LifecycleTableRecord,
    image_id: ImageId,
    image: Image,
) -> int | None:
    """Return the compiler guard shared by both routines in a table record."""

    if record.initialization is None or record.finalization is None:
        return None
    initialization_guard, initialization_error = _unique_guard_update(
        record.initialization,
        image_id,
        image,
        _is_initialization_guard_update,
    )
    finalization_guard, finalization_error = _unique_guard_update(
        record.finalization,
        image_id,
        image,
        _is_finalization_guard_update,
    )
    if (
        initialization_error is not None
        or finalization_error is not None
        or initialization_guard != finalization_guard
        or initialization_guard is None
        or not _is_writable_data_address(image, initialization_guard)
    ):
        return None
    return initialization_guard


# pylint: disable-next=too-many-positional-arguments,too-many-locals
def _match_delphi_lifecycle_data_layout(
    db: EntityDb,
    original_table: tuple[_LifecycleTableRecord, ...],
    recompiled_table: tuple[_LifecycleTableRecord, ...],
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol,
) -> None:
    """Associate anonymous records through a stable compiler-guard span.

    Matched lifecycle guards are DATA-layout anchors.  An intervening original
    guard is projected only when its immediate matched guard neighbours have
    the same displacement and exactly one unmatched rebuilt lifecycle record
    references the projected writable DWORD.  This recovers unit identity
    without depending on IDR's anonymous ``UnitNN`` label or a build-specific
    TD32 guard name.
    """

    recompiled_record_by_function: dict[int, int] = {}
    for index, record in enumerate(recompiled_table):
        for entity in (record.initialization, record.finalization):
            if entity is not None and entity.recomp_addr is not None:
                recompiled_record_by_function[entity.recomp_addr] = index

    guard_anchors: list[tuple[int, int]] = []
    for original_record in original_table:
        recompiled_index = _lifecycle_record_match_index(
            original_record, recompiled_record_by_function
        )
        if recompiled_index is None:
            continue
        original_guard = _lifecycle_record_guard(
            original_record, ImageId.ORIG, original_image
        )
        recompiled_guard = _lifecycle_record_guard(
            recompiled_table[recompiled_index],
            ImageId.RECOMP,
            recompiled_image,
        )
        if original_guard is not None and recompiled_guard is not None:
            guard_anchors.append((original_guard, recompiled_guard))
    guard_anchors.sort()
    if len(guard_anchors) < 2:
        return
    anchor_addresses = [original_guard for original_guard, _ in guard_anchors]

    recompiled_records_by_guard: defaultdict[int, list[_LifecycleTableRecord]] = (
        defaultdict(list)
    )
    for record in recompiled_table:
        if any(
            entity is not None and entity.matched
            for entity in (record.initialization, record.finalization)
        ):
            continue
        guard = _lifecycle_record_guard(record, ImageId.RECOMP, recompiled_image)
        if guard is not None:
            recompiled_records_by_guard[guard].append(record)

    proposals: list[tuple[ReccmpEntity, ReccmpEntity, str]] = []
    proposed_recompiled: set[int] = set()
    for original_record in original_table:
        entities = [
            entity
            for entity in (original_record.initialization, original_record.finalization)
            if entity is not None
        ]
        if not entities or any(entity.matched for entity in entities):
            continue
        owners = {_lifecycle_original_owner(entity) for entity in entities}
        if len(owners) != 1:
            continue
        original_owner = next(iter(owners))
        if (
            not isinstance(original_owner, str)
            or ANONYMOUS_DELPHI_UNIT_RE.fullmatch(original_owner) is None
        ):
            continue

        original_guard = _lifecycle_record_guard(
            original_record, ImageId.ORIG, original_image
        )
        if original_guard is None:
            continue
        insertion_index = bisect_left(anchor_addresses, original_guard)
        if insertion_index == 0 or insertion_index == len(guard_anchors):
            continue
        previous_original, previous_recompiled = guard_anchors[insertion_index - 1]
        following_original, following_recompiled = guard_anchors[insertion_index]
        previous_displacement = previous_recompiled - previous_original
        following_displacement = following_recompiled - following_original
        if previous_displacement != following_displacement:
            continue

        projected_guard = original_guard + previous_displacement
        if not previous_recompiled < projected_guard < following_recompiled:
            continue
        candidates = recompiled_records_by_guard.get(projected_guard, [])
        if len(candidates) != 1:
            event = (
                ReccmpEvent.AMBIGUOUS_MATCH
                if len(candidates) > 1
                else ReccmpEvent.GENERAL_WARNING
            )
            report(
                event,
                _original_address(entities[0]),
                msg=(
                    "Rejected Delphi lifecycle DATA projection: "
                    f"found {len(candidates)} rebuilt records at guard 0x{projected_guard:x}"
                ),
            )
            continue

        record_proposals = _lifecycle_record_proposals(original_record, candidates[0])
        if record_proposals is None:
            continue
        if any(
            _recompiled_address(recompiled_entity) in proposed_recompiled
            or not _is_executable_range(
                original_image,
                _original_address(original_entity),
                original_entity.size(ImageId.ORIG)
                or original_entity.max_size(ImageId.ORIG)
                or 0,
            )
            or not _is_executable_range(
                recompiled_image,
                _recompiled_address(recompiled_entity),
                recompiled_entity.size(ImageId.RECOMP)
                or recompiled_entity.max_size(ImageId.RECOMP)
                or 0,
            )
            for original_entity, recompiled_entity, _ in record_proposals
        ):
            continue
        proposals.extend(record_proposals)
        proposed_recompiled.update(
            _recompiled_address(recompiled_entity)
            for _, recompiled_entity, _ in record_proposals
        )

    _commit_lifecycle_function_proposals(
        db, proposals, report, "stable lifecycle-guard DATA layout"
    )


def match_delphi_lifecycle_functions(
    db: EntityDb,
    original_image: Image,
    recompiled_image: Image,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    """Associate anonymous compiler lifecycle routines through unit tables.

    Already matched lifecycle records are exact anchors in each image's
    compiler-emitted unit table.  An anonymous record is associated only when
    it occupies the same ordinal in an equal-length span bounded by anchors
    that are consecutive in both table orders.  This intentionally rejects
    inserted, removed, or reordered unit spans.
    """

    original_table = _find_delphi_lifecycle_table(db, ImageId.ORIG, original_image)
    recompiled_table = _find_delphi_lifecycle_table(
        db, ImageId.RECOMP, recompiled_image
    )
    if original_table is None or recompiled_table is None:
        report(
            ReccmpEvent.GENERAL_WARNING,
            0,
            msg="Skipped Delphi lifecycle function matching: unique unit table not found",
        )
        return

    _match_delphi_lifecycle_code_boundaries(
        db,
        original_table,
        recompiled_table,
        original_image,
        recompiled_image,
        report,
    )
    _match_delphi_lifecycle_data_layout(
        db,
        original_table,
        recompiled_table,
        original_image,
        recompiled_image,
        report,
    )
    # Boundary matches become exact unit-table anchors for the stable-span pass.
    original_table = _find_delphi_lifecycle_table(db, ImageId.ORIG, original_image)
    recompiled_table = _find_delphi_lifecycle_table(
        db, ImageId.RECOMP, recompiled_image
    )
    assert original_table is not None and recompiled_table is not None

    recompiled_record_by_function: dict[int, int] = {}
    for index, record in enumerate(recompiled_table):
        for entity in (record.initialization, record.finalization):
            if entity is not None and entity.recomp_addr is not None:
                recompiled_record_by_function[entity.recomp_addr] = index

    anchor_by_original: dict[int, int] = {}
    for index, record in enumerate(original_table):
        recompiled_index = _lifecycle_record_match_index(
            record, recompiled_record_by_function
        )
        if recompiled_index is not None:
            anchor_by_original[index] = recompiled_index

    proposals: list[tuple[ReccmpEntity, ReccmpEntity, str]] = []
    proposed_originals: set[int] = set()
    proposed_recompiled: set[int] = set()

    def stage_record(original_index: int, recompiled_index: int) -> None:
        record_proposals = _lifecycle_record_proposals(
            original_table[original_index], recompiled_table[recompiled_index]
        )
        if record_proposals is None:
            return
        for original_entity, recompiled_entity, canonical_name in record_proposals:
            assert original_entity.orig_addr is not None
            assert recompiled_entity.recomp_addr is not None
            original_size = (
                original_entity.size(ImageId.ORIG)
                or original_entity.max_size(ImageId.ORIG)
                or 0
            )
            recompiled_size = (
                recompiled_entity.size(ImageId.RECOMP)
                or recompiled_entity.max_size(ImageId.RECOMP)
                or 0
            )
            if (
                original_entity.orig_addr in proposed_originals
                or recompiled_entity.recomp_addr in proposed_recompiled
                or not _is_executable_range(
                    original_image, original_entity.orig_addr, original_size
                )
                or not _is_executable_range(
                    recompiled_image, recompiled_entity.recomp_addr, recompiled_size
                )
            ):
                return
        for original_entity, recompiled_entity, canonical_name in record_proposals:
            assert original_entity.orig_addr is not None
            assert recompiled_entity.recomp_addr is not None
            proposals.append((original_entity, recompiled_entity, canonical_name))
            proposed_originals.add(original_entity.orig_addr)
            proposed_recompiled.add(recompiled_entity.recomp_addr)

    # If one half of an anchored record was already matched, the same table
    # record proves the other half without needing a surrounding span.
    for original_index, recompiled_index in anchor_by_original.items():
        stage_record(original_index, recompiled_index)

    original_anchors = sorted(anchor_by_original.items())
    recompiled_anchor_order = {
        anchor: rank
        for rank, anchor in enumerate(
            sorted(original_anchors, key=lambda item: item[1])
        )
    }
    for left, right in zip(original_anchors, original_anchors[1:]):
        original_left, recompiled_left = left
        original_right, recompiled_right = right
        if (
            recompiled_anchor_order[right] != recompiled_anchor_order[left] + 1
            or original_right - original_left != recompiled_right - recompiled_left
            or original_right <= original_left + 1
        ):
            continue
        for original_index, recompiled_index in zip(
            range(original_left + 1, original_right),
            range(recompiled_left + 1, recompiled_right),
        ):
            stage_record(original_index, recompiled_index)

    _commit_lifecycle_function_proposals(
        db, proposals, report, "anchored unit-table order"
    )


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
    match: ReccmpEntity,
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
    return bool(flags & ImageSectionFlags.WRITE) and not bool(
        flags & ImageSectionFlags.EXECUTE
    )


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

    lifecycle_functions: defaultdict[str, dict[str, list[tuple[str, ReccmpMatch]]]] = (
        defaultdict(lambda: {"initialization": [], "finalization": []})
    )

    for match in db.get_functions():
        identity = _lifecycle_identity(match)
        if identity is None:
            continue

        owner_unit, routine_key = identity
        lifecycle_functions[owner_unit.casefold()][routine_key].append(
            (owner_unit, match)
        )

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
            routine.get("owner_unit") is None
            or routine.get("owner_unit").casefold() != unit_key
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
                reason = (
                    f"initialization {init_error}"
                    if init_error is not None
                    else f"finalization {final_error}"
                )
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
        if _has_guard_match_conflict(
            original_entity, ImageId.ORIG, recompiled_guard
        ) or _has_guard_match_conflict(
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
