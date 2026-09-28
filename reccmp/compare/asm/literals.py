"""Identify scalar loads whose anonymous storage can be compared by value."""

import re
from typing import Protocol
from .types import DisasmLiteInst

_MEMORY_OPERAND = re.compile(r"(byte|word|dword|qword|xword) ptr \[(0x[0-9a-f]+)\]")
_SIZES = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xword": 10}


class LiteralLookup(Protocol):
    def __call__(
        self, addr: int, size: int, owning_function: int | None = None
    ) -> bytes | None: ...


def literal_read(inst: DisasmLiteInst) -> tuple[int, int] | None:
    """Return the address and width of a direct scalar load, if unambiguous.

    Use a deliberately small set of load instructions. Stores, address-taking,
    indirect control flow, segment overrides and indexed reads do not establish
    the contents of an anonymous scalar constant.
    """
    if inst.mnemonic in ("mov", "movzx", "movsx"):
        destination, separator, source = inst.op_str.partition(", ")
        if not separator or re.fullmatch(r"[a-z][a-z0-9]*", destination) is None:
            return None
    elif inst.mnemonic in ("fld", "fild"):
        source = inst.op_str
    else:
        return None

    match = _MEMORY_OPERAND.fullmatch(source)
    if match is None:
        return None

    return int(match[2], 16), _SIZES[match[1]]
