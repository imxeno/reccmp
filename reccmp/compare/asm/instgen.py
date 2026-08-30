"""Pre-parser for x86 instructions. Will identify data/jump tables used with
switch statements and local jump/call destinations."""

import re
import bisect
import struct
from functools import cache
from enum import Enum, auto
from typing import Iterable, Literal, NamedTuple
from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32  # type: ignore
from .const import JUMP_MNEMONICS
from .types import DisasmLiteInst


@cache
def get_disassembler(is_32: bool = True) -> Cs:
    return Cs(CS_ARCH_X86, CS_MODE_32 if is_32 else CS_MODE_16)


DisasmLiteTuple = tuple[int, int, str, str]

displacement_regex = re.compile(r".*\+ (0x[0-9a-f]+)\]")
absolute_pointer_regex = re.compile(r".*\[(0x[0-9a-f]+)\]")
immediate_regex = re.compile(r"(0x[0-9a-f]+)$")


class SectionType(Enum):
    CODE = auto()
    DATA_TAB = auto()
    ADDR_TAB = auto()
    EXCEPT_TAB = auto()


class CodeSection(NamedTuple):
    type: Literal[SectionType.CODE]
    contents: list[DisasmLiteInst]


TabSectionType = (
    Literal[SectionType.DATA_TAB]
    | Literal[SectionType.ADDR_TAB]
    | Literal[SectionType.EXCEPT_TAB]
)


class TabSection(NamedTuple):
    type: TabSectionType
    contents: list[tuple[int, int]]


FuncSection = CodeSection | TabSection


def stop_at_int3(
    disasm_lite_gen: Iterable[DisasmLiteTuple],
) -> Iterable[DisasmLiteTuple]:
    """Wrapper for capstone disasm_lite generator. We want to stop reading
    instructions if we hit the int3 instruction."""
    for inst in disasm_lite_gen:
        # inst[2] is the mnemonic
        if inst[2] == "int3":
            break

        yield inst


class InstructGen:
    # pylint: disable=too-many-instance-attributes,too-many-positional-arguments
    def __init__(
        self,
        blob: bytes,
        start: int,
        is_32bit: bool = True,
        code_references: Iterable[int] = (),
        relocation_sites: Iterable[int] = (),
    ) -> None:
        self.is_32bit = is_32bit
        self.blob = blob
        self.start = start
        self.end = len(blob) + start
        self.section_end: int = self.end
        self.code_tracks: list[list[DisasmLiteInst]] = []

        # Todo: Could be refactored later
        self.cur_addr: int = 0
        self.cur_section_type: SectionType = SectionType.CODE
        self.section_start = start

        self.sections: list[FuncSection] = []
        self.relocation_sites = frozenset(relocation_sites)
        self.exception_table_ends: dict[int, int] = {}

        self.confirmed_addrs: dict[int, SectionType] = {}
        for address in code_references:
            self._insert_confirmed_addr(address, SectionType.CODE)
        self._find_exception_tables()
        self.analysis()

    def _find_exception_tables(self) -> None:
        """Identify Delphi's inline typed-exception descriptor records."""

        if not self.is_32bit or not self.relocation_sites:
            return

        # A typed exception dispatcher is emitted as an external near jump,
        # immediately followed by a count and (class, handler) pointer pairs.
        # Both non-null class cells and every handler cell are PE relocations;
        # the handlers point back into this procedure.
        for offset in range(5, max(5, len(self.blob) - 3)):
            if self.blob[offset - 5] != 0xE9:
                continue
            jump_delta = struct.unpack_from("<i", self.blob, offset - 4)[0]
            jump_target = self.start + offset + jump_delta
            if self.start <= jump_target < self.end:
                continue

            count = struct.unpack_from("<L", self.blob, offset)[0]
            if not 1 <= count <= 16:
                continue
            end_offset = offset + 4 + count * 8
            if end_offset > len(self.blob):
                continue

            valid = True
            for index in range(count):
                class_offset = offset + 4 + index * 8
                handler_offset = class_offset + 4
                class_site = self.start + class_offset
                handler_site = self.start + handler_offset
                class_value = struct.unpack_from("<L", self.blob, class_offset)[0]
                handler_value = struct.unpack_from("<L", self.blob, handler_offset)[0]
                if class_value != 0 and class_site not in self.relocation_sites:
                    valid = False
                    break
                if (
                    handler_site not in self.relocation_sites
                    or not self.start <= handler_value < self.end
                ):
                    valid = False
                    break

            if not valid:
                continue

            table_start = self.start + offset
            table_end = self.start + end_offset
            self.exception_table_ends[table_start] = table_end
            self._insert_confirmed_addr(table_start, SectionType.EXCEPT_TAB)
            self._insert_confirmed_addr(table_end, SectionType.CODE)

    def _finish_code_section(self, contents: list[DisasmLiteInst]):
        self.sections.append(CodeSection(SectionType.CODE, contents))

    def _finish_tab_section(self, type_: TabSectionType, stuff: list[tuple[int, int]]):
        self.sections.append(TabSection(type_, stuff))

    def _insert_confirmed_addr(self, addr: int, type_: SectionType):
        # Ignore address outside the bounds of the function
        if not self.start <= addr < self.end:
            return

        self.confirmed_addrs[addr] = type_

        # This newly inserted address might signal the end of this section.
        # For example, a jump table at the end of the function means we should
        # stop reading instructions once we hit that address.
        # However, if there is a jump table in between code sections, we might
        # read a jump to an address back to the beginning of the function
        # (e.g. a loop that spans the entire function)
        # so ignore this address because we have already passed it.
        if type_ != self.cur_section_type and addr > self.cur_addr:
            self.section_end = min(self.section_end, addr)

    def _next_section(self, addr: int) -> SectionType | None:
        """We have reached the start of a new section. Tell what kind of
        data we are looking at (code or other) and how much we should read."""

        # Assume the start of every function is code.
        if addr == self.start:
            following = [
                confirmed
                for confirmed, section_type in self.confirmed_addrs.items()
                if confirmed > addr and section_type != SectionType.CODE
            ]
            self.section_end = min(following, default=self.end)
            return SectionType.CODE

        # The start of a new section must be an address that we've seen.
        new_type = self.confirmed_addrs.get(addr)
        if new_type is None:
            return None

        self.cur_section_type = new_type

        # The confirmed addrs dict is sorted by insertion order
        # i.e. the order in which we read the addresses
        # So we have to sort and then find the next item
        # to see where this section should end.

        # If we are in a CODE section, ignore contiguous CODE addresses.
        # These are not the start of a new section.
        # However: if we are not in CODE, any upcoming address is a new section.
        # Do this so we can detect contiguous non-CODE sections.
        confirmed = [
            conf_addr
            for (conf_addr, conf_type) in sorted(self.confirmed_addrs.items())
            if self.cur_section_type != SectionType.CODE
            or conf_type != self.cur_section_type
        ]

        index = bisect.bisect_right(confirmed, addr)
        if index < len(confirmed):
            self.section_end = confirmed[index]
        else:
            self.section_end = self.end

        return new_type

    def _get_code_for(self, addr: int) -> list[DisasmLiteInst]:
        """Start disassembling at the given address."""
        # If we are reading a code block beyond the first, see if we already
        # have disassembled instructions beginning at the specified address.
        # For a CODE/ADDR/CODE function, we might get lucky and produce the
        # correct instruction after the jump table's junk instructions.
        for track in self.code_tracks:
            for i, inst in enumerate(track):
                if inst.address == addr:
                    return track[i:]

        # If we are here, we don't have the instructions.
        # Todo: Could try to be clever here and disassemble only
        # as much as we probably need (i.e. if a jump table is between CODE
        # blocks, there are probably only a few bad instructions after the
        # jump table is finished. We could disassemble up to the next verified
        # code address and stitch it together)

        disassembler = get_disassembler(self.is_32bit)
        blob_cropped = self.blob[addr - self.start :]
        instructions = [
            DisasmLiteInst(*inst)
            for inst in stop_at_int3(disassembler.disasm_lite(blob_cropped, addr))
        ]
        self.code_tracks.append(instructions)
        return instructions

    def _handle_jump(self, inst: DisasmLiteInst):
        # If this is a regular jump and its destination is within the
        # bounds of the binary data (i.e. presumed function size)
        # add it to our list of confirmed addresses.
        if inst.op_str[0] == "0":
            value = int(inst.op_str, 16)
            self._insert_confirmed_addr(value, SectionType.CODE)

        # If this is jumping into a table of addresses, save the destination
        elif (match := displacement_regex.match(inst.op_str)) is not None:
            value = int(match.group(1), 16)
            self._insert_confirmed_addr(value, SectionType.ADDR_TAB)

    def analysis(self):
        # pylint: disable=too-many-nested-blocks
        self.cur_addr = self.start

        while (sect_type := self._next_section(self.cur_addr)) is not None:
            self.section_start = self.cur_addr

            if sect_type == SectionType.CODE:
                instructions = self._get_code_for(self.cur_addr)

                # If we didn't get any instructions back, something is wrong.
                # i.e. We can only read part of the full instruction that is up next.
                if len(instructions) == 0:
                    # Nudge the current addr so we will eventually move on to the
                    # next section.
                    # Todo: Maybe we could just call it quits here
                    self.cur_addr += 1
                    break

                for inst in instructions:
                    # section_end is updated as we read instructions.
                    # If we are into a jump/data table and would read
                    # a junk instruction, stop here.
                    if self.cur_addr >= self.section_end:
                        break

                    # print(f"{inst.address:x} : {inst.mnemonic} {inst.op_str}")

                    if inst.mnemonic in JUMP_MNEMONICS:
                        self._handle_jump(inst)
                        # Todo: log calls too (unwind section)
                    elif inst.mnemonic in ("mov", "movzx"):
                        # Todo: maintain pairing of data/jump tables
                        if (match := displacement_regex.match(inst.op_str)) is not None:
                            value = int(match.group(1), 16)
                            self._insert_confirmed_addr(value, SectionType.DATA_TAB)
                        elif (
                            match := absolute_pointer_regex.match(inst.op_str)
                        ) is not None:
                            # Delphi commonly emits local byte/word lookup
                            # tables after RET and addresses them directly,
                            # e.g. ``mov al, byte ptr [function_tail]``.
                            value = int(match.group(1), 16)
                            self._insert_confirmed_addr(value, SectionType.DATA_TAB)
                        elif (
                            any(
                                inst.address <= site < inst.address + inst.size
                                for site in self.relocation_sites
                            )
                            and (match := immediate_regex.search(inst.op_str))
                            is not None
                        ):
                            value = int(match.group(1), 16)
                            self._insert_confirmed_addr(value, SectionType.DATA_TAB)
                    elif inst.mnemonic == "lea":
                        # Delphi's hand-written RTL assembly loads both local
                        # jump-table bases and inline byte-table bases with
                        # LEA before dispatching through a register.
                        if (match := displacement_regex.match(inst.op_str)) is not None:
                            value = int(match.group(1), 16)
                            value_offset = value - self.start
                            if 0 <= value_offset <= len(self.blob) - 4:
                                first_value = struct.unpack_from(
                                    "<L", self.blob, value_offset
                                )[0]
                                table_type = (
                                    SectionType.ADDR_TAB
                                    if value in self.relocation_sites
                                    or self.start <= first_value < self.end
                                    else SectionType.DATA_TAB
                                )
                                self._insert_confirmed_addr(value, table_type)

                    # Do this instead of copying instruction address.
                    # If there is only one instruction, we would get stuck here.
                    self.cur_addr += inst.size

                # End of for loop on instructions.
                # We are at the end of the section or the entire function.
                # Cut out only the valid instructions for this section
                # and save it for later.

                # A disassembled instruction may begin in alignment padding
                # and straddle a newly discovered inline-table boundary.
                # Resume at the proven boundary rather than after that bogus
                # cross-boundary instruction.
                self.cur_addr = min(self.cur_addr, self.section_end)

                # Todo: don't need to iter on every instruction here.
                # They are already in order.
                instruction_slice = [
                    inst
                    for inst in instructions
                    if inst.address + inst.size <= self.section_end
                ]
                self._finish_code_section(instruction_slice)

            elif sect_type == SectionType.ADDR_TAB:
                # Clamp to multiple of 4 (dwords)
                read_size = ((self.section_end - self.cur_addr) // 4) * 4
                offsets = range(self.section_start, self.section_start + read_size, 4)
                dwords = self.blob[
                    self.cur_addr - self.start : self.cur_addr - self.start + read_size
                ]
                addrs: list[int] = []
                table_is_function_local: bool | None = None
                for (addr,) in struct.iter_unpack("<L", dwords):
                    # A compiler-emitted switch table contains code addresses
                    # in the current function.  If no later section boundary
                    # was known when we entered the table, do not consume the
                    # following code (or literal data) as bogus table entries.
                    is_function_local = self.start <= addr < self.end
                    if table_is_function_local is None:
                        table_is_function_local = is_function_local
                    if table_is_function_local and not is_function_local:
                        break

                    addrs.append(addr)
                    # Todo: the fact that these are jump table destinations
                    # should factor into the label name.
                    self._insert_confirmed_addr(addr, SectionType.CODE)

                jump_table = list(zip(offsets, addrs))
                # for (t0,t1) in jump_table:
                #     print(f"{t0:x} : --> {t1:x}")

                self._finish_tab_section(SectionType.ADDR_TAB, jump_table)
                self.cur_addr = self.section_start + len(addrs) * 4

            elif sect_type == SectionType.EXCEPT_TAB:
                table_end = self.exception_table_ends[self.section_start]
                read_size = table_end - self.cur_addr
                dwords = self.blob[
                    self.cur_addr - self.start : self.cur_addr - self.start + read_size
                ]
                offsets = range(self.section_start, table_end, 4)
                values = [value for value, in struct.iter_unpack("<L", dwords)]
                self._finish_tab_section(
                    SectionType.EXCEPT_TAB, list(zip(offsets, values))
                )
                self.cur_addr = table_end

            else:
                # Todo: variable data size?
                read_size = self.section_end - self.cur_addr
                offsets = range(self.section_start, self.section_start + read_size)
                bytes_ = self.blob[
                    self.cur_addr - self.start : self.cur_addr - self.start + read_size
                ]
                data = [b for b, in struct.iter_unpack("<B", bytes_)]

                data_table = list(zip(offsets, data))
                # for (t0,t1) in data_table:
                #     print(f"{t0:x} : value {t1:02x}")

                self._finish_tab_section(SectionType.DATA_TAB, data_table)
                self.cur_addr = self.section_end
