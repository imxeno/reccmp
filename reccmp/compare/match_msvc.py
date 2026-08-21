from bisect import bisect_left
from collections import defaultdict, deque
import re
from reccmp.types import EntityType
from reccmp.compare.db import EntityDb
from reccmp.compare.lines import LinesDb
from reccmp.compare.event import (
    ReccmpEvent,
    ReccmpReportProtocol,
    reccmp_report_nop,
)
from reccmp.compare.queries import get_referencing_entity_matches
from reccmp.delphi.td32 import (
    normalize_delphi_name,
    qualify_delphi_function_name,
)
from reccmp.types import ImageId

DELPHI_IDR_PLACEHOLDER_RE = re.compile(
    r"^(?P<owner>.+)\.sub_(?P<address>[0-9a-f]{8})_(?P=address)$", re.IGNORECASE
)


class EntityIndex:
    """One-to-many index. Maps string value to address."""

    _dict: dict[str, list[int]]

    def __init__(self) -> None:
        self._dict = {}

    def __contains__(self, key: str) -> bool:
        return key in self._dict

    def add(self, key: str, value: int):
        self._dict.setdefault(key, []).append(value)

    def get(self, key: str) -> list[int]:
        return self._dict.get(key, [])

    def count(self, key: str) -> int:
        return len(self._dict.get(key, []))

    def pop(self, key: str) -> int:
        value = self._dict[key].pop(0)
        if len(self._dict[key]) == 0:
            del self._dict[key]

        return value

    def discard(self, key: str, value: int):
        values = self._dict.get(key)
        if values is None:
            return

        try:
            values.remove(value)
        except ValueError:
            return

        if not values:
            del self._dict[key]


def match_symbols(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
    *,
    truncate: bool = False,
):
    """Match all entities with the 'symbol' attribute set. We expect this value to be unique."""

    symbol_index = EntityIndex()

    for ent in db.unmatched(ImageId.RECOMP):
        symbol = ent.get("symbol")
        if not symbol:
            continue

        # Truncate symbol to 255 chars for older MSVC. See also: Warning C4786.
        if truncate:
            symbol = symbol[:255]

        assert ent.recomp_addr is not None
        symbol_index.add(symbol, ent.recomp_addr)

    with db.batch() as batch:
        for ent in db.unmatched(ImageId.ORIG):
            assert ent.orig_addr is not None
            symbol = ent.get("symbol")

            if not symbol:
                continue

            # Repeat the truncate for our match search
            if truncate:
                symbol = symbol[:255]

            if symbol in symbol_index:
                recomp_addr = symbol_index.pop(symbol)

                # If match was not unique:
                if symbol in symbol_index:
                    report(
                        ReccmpEvent.NON_UNIQUE_SYMBOL,
                        ent.orig_addr,
                        msg=f"Matched 0x{ent.orig_addr:x} using non-unique symbol '{symbol}'",
                    )

                batch.match(ent.orig_addr, recomp_addr)

            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    ent.orig_addr,
                    msg=f"Failed to match at 0x{ent.orig_addr:x} with symbol '{symbol}'",
                )


def match_functions(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
    *,
    truncate: bool = False,
):
    # addr->symbol map. Used later in error message for non-unique match.
    recomp_symbols: dict[int, str] = {}
    recomp_names: dict[int, str] = {}

    name_index = EntityIndex()
    delphi_name_index = EntityIndex()

    # TODO: We allow a match if entity_type is null.
    # This can be removed if we can more confidently declare a symbol is a function
    # when adding from the PDB.
    for ent in db.unmatched(ImageId.RECOMP):
        symbol = ent.get("symbol")
        name = ent.get("name")
        if ent.get("type") and ent.get("type") != EntityType.FUNCTION:
            continue

        if not name:
            continue

        # Truncate function name to 255 chars for older MSVC. See also: Warning C4786.
        if truncate:
            name = name[:255]

        assert ent.recomp_addr is not None
        name_index.add(name, ent.recomp_addr)
        recomp_names[ent.recomp_addr] = name

        delphi_name = normalize_delphi_name(name)
        if delphi_name is not None:
            delphi_name_index.add(delphi_name.casefold(), ent.recomp_addr)

        # Get the symbol for the error message later.
        if symbol is not None:
            recomp_symbols[ent.recomp_addr] = symbol

    # Report if the name used in the match is not unique.
    # If the name list contained multiple addresses at the start,
    # we should report even for the last address in the list.
    non_unique_names = set()

    with db.batch() as batch:
        for ent in db.unmatched(ImageId.ORIG):
            name = ent.get("name")
            if ent.get("type") != EntityType.FUNCTION:
                continue

            if not name:
                continue

            assert ent.orig_addr is not None

            # Repeat the truncate for our match search
            if truncate:
                name = name[:255]

            if name in name_index:
                exact_candidates = name_index.get(name)
                if (
                    ent.get("library")
                    and len(exact_candidates) > 1
                    and all(
                        (candidate := db.get(ImageId.RECOMP, address)) is not None
                        and candidate.get("is_delphi")
                        for address in exact_candidates
                    )
                ):
                    report(
                        ReccmpEvent.AMBIGUOUS_MATCH,
                        ent.orig_addr,
                        msg=(
                            f"Deferred ambiguous Delphi library name '{name}' "
                            f"with {len(exact_candidates)} rebuilt candidates"
                        ),
                    )
                    continue

                recomp_addr = name_index.pop(name)
                recomp_delphi_name = normalize_delphi_name(recomp_names[recomp_addr])
                if recomp_delphi_name is not None:
                    delphi_name_index.discard(
                        recomp_delphi_name.casefold(), recomp_addr
                    )
                # If match was not unique
                if name in name_index:
                    non_unique_names.add(name)

                # If this name was ever matched non-uniquely
                if name in non_unique_names:
                    matched_symbol = recomp_symbols.get(recomp_addr, "None")
                    other_symbols = [
                        recomp_symbols.get(recomp_addr, "None")
                        for recomp_addr in name_index.get(name)
                    ]
                    report(
                        ReccmpEvent.AMBIGUOUS_MATCH,
                        ent.orig_addr,
                        msg=f"Ambiguous match 0x{ent.orig_addr:x} on name '{name}' to\n"
                        + f"'{matched_symbol}'\n"
                        + "Other candidates:\n"
                        + ",\n".join(f"'{candidate}'" for candidate in other_symbols),
                    )

                batch.match(ent.orig_addr, recomp_addr)
                continue

            # Delphi is case-insensitive, and IDR retains decoration that TD32
            # removes (e.g. System.@ClassDestroy_00404754 versus
            # System.ClassDestroy). Restrict this fallback to compiler-decorated
            # names that contain ``@`` so ordinary C/C++ names and IDR's generic
            # address-suffixed aliases retain their existing match behavior.
            delphi_name = normalize_delphi_name(name)
            if delphi_name is not None and delphi_name != name and "@" in name:
                delphi_key = delphi_name.casefold()
                if delphi_key in delphi_name_index:
                    delphi_candidates = delphi_name_index.get(delphi_key)
                    if (
                        ent.get("library")
                        and len(delphi_candidates) > 1
                        and all(
                            (candidate := db.get(ImageId.RECOMP, address)) is not None
                            and candidate.get("is_delphi")
                            for address in delphi_candidates
                        )
                    ):
                        report(
                            ReccmpEvent.AMBIGUOUS_MATCH,
                            ent.orig_addr,
                            msg=(
                                "Deferred ambiguous Delphi library name "
                                f"'{delphi_name}' with "
                                f"{len(delphi_candidates)} rebuilt candidates"
                            ),
                        )
                        continue

                    recomp_addr = delphi_name_index.pop(delphi_key)
                    name_index.discard(recomp_names[recomp_addr], recomp_addr)

                    if delphi_key in delphi_name_index:
                        matched_symbol = recomp_symbols.get(recomp_addr, "None")
                        other_symbols = [
                            recomp_symbols.get(candidate_addr, "None")
                            for candidate_addr in delphi_name_index.get(delphi_key)
                        ]
                        report(
                            ReccmpEvent.AMBIGUOUS_MATCH,
                            ent.orig_addr,
                            msg=(
                                f"Ambiguous Delphi match 0x{ent.orig_addr:x} "
                                f"on normalized name '{delphi_name}' to\n"
                                f"'{matched_symbol}'\n"
                                "Other candidates:\n"
                                + ",\n".join(
                                    f"'{candidate}'" for candidate in other_symbols
                                )
                            ),
                        )

                    batch.match(ent.orig_addr, recomp_addr)
                    continue

            report(
                ReccmpEvent.NO_MATCH,
                ent.orig_addr,
                msg=f"Failed to match function at 0x{ent.orig_addr:x} with name '{name}'",
            )


def match_delphi_idr_placeholders(db: EntityDb):
    """Match address-named IDR functions inside stable Delphi layout spans.

    IDR names such as ``System.sub_004017F4_004017F4`` contain no semantic
    name to compare with TD32's ``System.FreeSpace``. Infer the correspondence
    only when matched functions on both sides of the placeholder establish the
    same address displacement, and the predicted TD32 function has the same
    owner and exact size. This keeps the fallback deterministic and avoids
    guessing from a commonly repeated function size.
    """

    anchors_by_owner: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
    for matched_entity in db.get_matches():
        owner_unit = matched_entity.get("owner_unit")
        if (
            matched_entity.get("type") == EntityType.FUNCTION
            and matched_entity.get("is_delphi")
            and isinstance(owner_unit, str)
        ):
            anchors_by_owner[owner_unit.casefold()].append(
                (matched_entity.orig_addr, matched_entity.recomp_addr)
            )

    anchor_orig_addrs: dict[str, list[int]] = {}
    for owner_key, owner_anchors in anchors_by_owner.items():
        owner_anchors.sort()
        anchor_orig_addrs[owner_key] = [orig_addr for orig_addr, _ in owner_anchors]

    recomp_by_addr = {
        ent.recomp_addr: ent
        for ent in db.unmatched(ImageId.RECOMP)
        if ent.get("type") == EntityType.FUNCTION and ent.get("is_delphi")
    }

    with db.batch() as batch:
        for ent in db.unmatched(ImageId.ORIG):
            if ent.get("type") != EntityType.FUNCTION:
                continue

            name = ent.get("name")
            if not isinstance(name, str):
                continue

            placeholder = DELPHI_IDR_PLACEHOLDER_RE.fullmatch(name)
            if placeholder is None:
                continue

            assert ent.orig_addr is not None
            if int(placeholder.group("address"), 16) != ent.orig_addr:
                continue

            owner_key = placeholder.group("owner").casefold()
            anchors = anchors_by_owner.get(owner_key)
            orig_addrs = anchor_orig_addrs.get(owner_key)
            if not anchors or not orig_addrs:
                continue

            insertion_index = bisect_left(orig_addrs, ent.orig_addr)
            if insertion_index == 0 or insertion_index == len(anchors):
                continue

            previous_orig, previous_recomp = anchors[insertion_index - 1]
            next_orig, next_recomp = anchors[insertion_index]
            previous_displacement = previous_recomp - previous_orig
            next_displacement = next_recomp - next_orig
            if previous_displacement != next_displacement:
                continue

            recomp_addr = ent.orig_addr + previous_displacement
            candidate = recomp_by_addr.get(recomp_addr)
            if candidate is None:
                continue

            candidate_owner = candidate.get("owner_unit")
            if (
                not isinstance(candidate_owner, str)
                or candidate_owner.casefold() != owner_key
            ):
                continue

            orig_size = ent.size(ImageId.ORIG)
            recomp_size = candidate.size(ImageId.RECOMP)
            if orig_size is None or orig_size <= 0 or orig_size != recomp_size:
                continue

            batch.match(ent.orig_addr, recomp_addr)


def match_vtables(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    """The requirements for matching are:
    1.  Recomp entity has name attribute in this format: "Pizza::`vftable'"
        This is derived from the symbol: "??_7Pizza@@6B@"
    2.  Orig entity has name attribute with class name only. (e.g. "Pizza")
    3.  If multiple inheritance is used, the orig entity has the base_class attribute set.

    For multiple inheritance, the vtable name references the base class like this:

        - X::`vftable'{for `Y'}

    The vtable for the derived class will take one of these forms:

        - X::`vftable'{for `X'}
        - X::`vftable'

    We assume only one of the above will appear for a given class."""

    vtable_name_index = EntityIndex()
    delphi_vtable_name_index = EntityIndex()
    delphi_short_vtable_name_index = EntityIndex()
    delphi_vtable_aliases: dict[int, tuple[str | None, str]] = {}

    for ent in db.unmatched(ImageId.RECOMP):
        name = ent.get("name")
        if not name or ent.get("type") != EntityType.VTABLE:
            continue

        assert ent.recomp_addr is not None
        vtable_name_index.add(name, ent.recomp_addr)
        delphi_name = normalize_delphi_name(name)
        if delphi_name and ("." in delphi_name or ent.get("is_delphi")):
            short_name = delphi_name.rsplit(".", 1)[-1]
            full_key = delphi_name.casefold() if "." in delphi_name else None
            short_key = short_name.casefold()
            if full_key is not None:
                delphi_vtable_name_index.add(full_key, ent.recomp_addr)
            delphi_short_vtable_name_index.add(short_key, ent.recomp_addr)
            delphi_vtable_aliases[ent.recomp_addr] = (full_key, short_key)

    def discard_delphi_vtable_aliases(recomp_addr: int):
        full_key, short_key = delphi_vtable_aliases[recomp_addr]
        if full_key is not None:
            delphi_vtable_name_index.discard(full_key, recomp_addr)
        delphi_short_vtable_name_index.discard(short_key, recomp_addr)

    with db.batch() as batch:
        for ent in db.unmatched(ImageId.ORIG):
            class_name = ent.get("name")
            if not class_name or ent.get("type") != EntityType.VTABLE:
                continue

            assert ent.orig_addr is not None

            base_class = ent.get("base_class")

            # Most classes will not use multiple inheritance, so try the regular vtable
            # first, unless a base class is provided.
            if base_class is None or base_class == class_name:
                bare_vftable = f"{class_name}::`vftable'"

                if bare_vftable in vtable_name_index:
                    recomp_addr = vtable_name_index.pop(bare_vftable)
                    batch.match(ent.orig_addr, recomp_addr)
                    continue

            # If we didn't find a match above, search for the multiple inheritance vtable.
            for_name = base_class if base_class is not None else class_name
            for_vftable = f"{class_name}::`vftable'{{for `{for_name}'}}"

            if for_vftable in vtable_name_index:
                recomp_addr = vtable_name_index.pop(for_vftable)
                batch.match(ent.orig_addr, recomp_addr)
                continue

            delphi_class_name = normalize_delphi_name(class_name)
            if delphi_class_name:
                full_key = delphi_class_name.casefold()
                if full_key in delphi_vtable_name_index:
                    recomp_addr = delphi_vtable_name_index.pop(full_key)
                    discard_delphi_vtable_aliases(recomp_addr)
                    batch.match(ent.orig_addr, recomp_addr)
                    continue

                # Some Delphi 7 TD32 class records expose only ``TWidget``
                # while source VTABLE markers retain ``Unit1.TWidget``. Match
                # through the short class name only when it is unique.
                short_key = delphi_class_name.rsplit(".", 1)[-1].casefold()
                if delphi_short_vtable_name_index.count(short_key) == 1:
                    recomp_addr = delphi_short_vtable_name_index.pop(short_key)
                    discard_delphi_vtable_aliases(recomp_addr)
                    batch.match(ent.orig_addr, recomp_addr)
                    continue

            report(
                ReccmpEvent.NO_MATCH,
                ent.orig_addr,
                msg=f"Failed to match vtable at 0x{ent.orig_addr:x} for class '{class_name}' (base={base_class or 'None'})",
            )


def match_static_variables(
    db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop
):
    """To match a static variable, we need the following:
    1. Orig entity function with symbol
    2. Orig entity variable with:
        - name = name of variable
        - static_var = True
        - parent_function = orig address of function
    3. Recomp entity for the static variable with symbol

    Requirement #1 is most likely to be met by matching the entity with recomp data.
    Therefore, this function should be called after match_symbols or match_functions."""
    symbols = {}

    for recomp_ent in db.unmatched(ImageId.RECOMP):
        if recomp_ent.get("type") and recomp_ent.get("type") != EntityType.DATA:
            continue

        recomp_sym = recomp_ent.get("symbol")
        if not recomp_sym:
            continue

        assert recomp_ent.recomp_addr is not None
        symbols[recomp_ent.recomp_addr] = recomp_sym

    with db.batch() as batch:
        for variable_ent in db.unmatched(ImageId.ORIG):
            variable_addr = variable_ent.orig_addr
            assert variable_addr is not None

            if not variable_ent.get("static_var"):
                continue

            variable_name = variable_ent.get("name")
            if not variable_name:
                continue

            function_name = None
            function_symbol = None

            parent_addr = variable_ent.get("parent_function")
            if parent_addr:
                parent_ent = db.get(ImageId.ORIG, parent_addr)
                if parent_ent is not None:
                    function_name = parent_ent.get("name")
                    function_symbol = parent_ent.get("symbol")

            # If we could not find the parent function, or if it has no symbol:
            if function_symbol is None:
                report(
                    ReccmpEvent.NO_MATCH,
                    variable_addr,
                    msg=f"No function for static variable '{variable_name}'",
                )
                continue

            for recomp_addr, recomp_sym in symbols.items():
                if function_symbol in recomp_sym and variable_name in recomp_sym:
                    batch.match(variable_addr, recomp_addr)
                    del symbols[recomp_addr]
                    break
            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    variable_addr,
                    msg=f"Failed to match static variable {variable_name} from function {function_name} annotated with 0x{variable_addr:x}",
                )


def match_variables(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    var_name_index = EntityIndex()

    # TODO: We allow a match if entity_type is null.
    # This can be removed if we can more confidently declare a symbol is a variable
    # when adding from the PDB.
    for ent in db.unmatched(ImageId.RECOMP):
        if ent.get("type") and ent.get("type") != EntityType.DATA:
            continue

        name = ent.get("name")
        if not name:
            continue

        assert ent.recomp_addr is not None
        var_name_index.add(name, ent.recomp_addr)

    # Preserve the established exact-name behavior as the first pass. Committing
    # these matches before building the Delphi index also lets exact matches
    # disambiguate otherwise identical unit-qualified candidates.
    with db.batch() as batch:
        for ent in db.unmatched(ImageId.ORIG):
            if ent.get("type") != EntityType.DATA:
                continue

            name = ent.get("name")
            if not name:
                continue

            if ent.get("static_var"):
                continue

            assert ent.orig_addr is not None

            if name in var_name_index:
                recomp_addr = var_name_index.pop(name)
                batch.match(ent.orig_addr, recomp_addr)

    delphi_qualified_index = EntityIndex()
    for ent in db.unmatched(ImageId.RECOMP):
        if ent.get("type") and ent.get("type") != EntityType.DATA:
            continue

        name = ent.get("name")
        owner_unit = ent.get("owner_unit")
        if not name or not ent.get("is_delphi") or not owner_unit:
            continue

        qualified_name = qualify_delphi_function_name(owner_unit, name)
        if qualified_name is not None:
            assert ent.recomp_addr is not None
            delphi_qualified_index.add(qualified_name.casefold(), ent.recomp_addr)

    with db.batch() as batch:
        for ent in db.unmatched(ImageId.ORIG):
            if ent.get("type") != EntityType.DATA or ent.get("static_var"):
                continue

            name = ent.get("name")
            if not name:
                continue

            assert ent.orig_addr is not None

            qualified_candidates = delphi_qualified_index.get(name.casefold())
            if len(qualified_candidates) == 1:
                recomp_addr = delphi_qualified_index.pop(name.casefold())
                batch.set(
                    ImageId.RECOMP,
                    recomp_addr,
                    computed_name=name,
                )
                batch.match(ent.orig_addr, recomp_addr)
            elif len(qualified_candidates) > 1:
                report(
                    ReccmpEvent.AMBIGUOUS_MATCH,
                    ent.orig_addr,
                    msg=(
                        f"Delphi variable {name} at 0x{ent.orig_addr:x} "
                        "has multiple unit-qualified matches"
                    ),
                )
            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    ent.orig_addr,
                    msg=f"Failed to match variable {name} at 0x{ent.orig_addr:x}",
                )


def match_strings(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    string_index = EntityIndex()

    for ent in db.unmatched(ImageId.RECOMP):
        if ent.get("type") not in (EntityType.STRING, EntityType.WIDECHAR):
            continue

        text = ent.get("name")
        if not text:
            continue

        assert ent.recomp_addr is not None
        string_index.add(text, ent.recomp_addr)

    with db.batch() as batch:
        for ent in db.unmatched(ImageId.ORIG):
            if ent.get("type") not in (EntityType.STRING, EntityType.WIDECHAR):
                continue

            text = ent.get("name")
            if not text:
                continue

            verified = ent.get("verified", False)
            assert ent.orig_addr is not None

            if text in string_index:
                recomp_addr = string_index.pop(text)
                batch.match(ent.orig_addr, recomp_addr)
            elif verified:
                report(
                    ReccmpEvent.NO_MATCH,
                    ent.orig_addr,
                    msg=f"Failed to match string {text} at 0x{ent.orig_addr:x}",
                )


def match_lines(
    db: EntityDb,
    lines: LinesDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    """
    This function requires access to `cv` and `recomp_bin` because most lines will not have an annotation.
    It would therefore be quite inefficient to load all recomp lines into the `entities` table
    and only match a tiny fraction of them to symbols.
    """

    with db.batch() as batch:
        for ent in db.unmatched(ImageId.ORIG):
            if ent.get("type") != EntityType.LINE:
                continue

            assert ent.orig_addr is not None
            filename = ent.get("filename")
            line = ent.get("line")

            #
            # We only match the line directly below the annotation since not all lines of code result in a debug line, especially if optimizations are turned on.
            # However, this does cause false positives in cases like
            # ```
            # // LINE: TARGET 0x1234
            # // OTHER_ANNOTATION: ...
            # actual_code();
            # ```
            # or
            # ```
            # // LINE: TARGET 0x1234
            #
            # actual_code();
            # ```
            # but it is significantly more effort to detect these false positives.
            #

            # We match `line + 1` since `line` is the comment itself
            for recomp_addr in lines.search_line(filename, line + 1):
                batch.match(ent.orig_addr, recomp_addr)
                break
            else:
                # No results
                report(
                    ReccmpEvent.NO_MATCH,
                    ent.orig_addr,
                    f"Found no matching debug symbol for {filename}:{line}",
                )


def match_ref(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    """Matches child entities that refer to the same parent entity.
    Repeats until there are no new matches."""
    new_matches = False

    for _ in range(10):
        new_matches = False
        with db.batch() as batch:
            for orig_addr, recomp_addr in get_referencing_entity_matches(db):
                new_matches = True
                batch.match(orig_addr, recomp_addr)

            if not new_matches:
                break

    # If we did not break out of the loop:
    if new_matches:
        report(
            ReccmpEvent.GENERAL_WARNING,
            -1,
            "Reached maximum iteration depth while matching referencing entities.",
        )


def match_imports(db: EntityDb):
    orig_imports_by_name: defaultdict[str, deque[int]] = defaultdict(deque)

    # n.b. Case insensitive match here to preserve previous behavior.
    # The final entity will use the name from the recomp side.
    for ent in db.unmatched(ImageId.ORIG):
        if ent.get("type") != EntityType.IMPORT:
            continue

        name = ent.get("name")
        if not name:
            continue

        assert isinstance(ent.orig_addr, int)
        orig_imports_by_name[name.upper()].append(ent.orig_addr)

    with db.batch() as batch:
        for ent in db.unmatched(ImageId.RECOMP):
            if ent.get("type") != EntityType.IMPORT:
                continue

            name = ent.get("name")
            if not name:
                continue

            orig_addrs = orig_imports_by_name.get(name.upper())
            if orig_addrs:
                orig_addr = orig_addrs.popleft()
                assert isinstance(ent.recomp_addr, int)
                batch.match(orig_addr, ent.recomp_addr)
