"""Calling-convention helpers shared by debug extraction and Ghidra import."""

from __future__ import annotations

from .exceptions import ReccmpGhidraException

BORLAND_REGISTER_CALL_TYPE = "__borland_register"

_DEBUG_CALL_TYPE_TO_GHIDRA = {
    "ThisCall": "__thiscall",
    "C Near": "default",
    "STD Near": "__stdcall",
    "Fast Near": "__fastcall",
    "Near C": "__cdecl",
    "Near Fast": "__fastcall",
    "Near Std": "__stdcall",
    "Borland Register": BORLAND_REGISTER_CALL_TYPE,
}

_REGISTER_ALIASES = {
    "al": "eax",
    "ah": "eax",
    "ax": "eax",
    "eax": "eax",
    "cl": "ecx",
    "ch": "ecx",
    "cx": "ecx",
    "ecx": "ecx",
    "dl": "edx",
    "dh": "edx",
    "dx": "edx",
    "edx": "edx",
    "bl": "ebx",
    "bh": "ebx",
    "bx": "ebx",
    "ebx": "ebx",
    "sp": "esp",
    "esp": "esp",
    "bp": "ebp",
    "ebp": "ebp",
    "si": "esi",
    "esi": "esi",
    "di": "edi",
    "edi": "edi",
}

_BORLAND_REGISTER_PROTOTYPE_XML = """
<prototype name="__borland_register" extrapop="unknown" stackshift="4">
  <input>
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
    <pentry minsize="1" maxsize="4">
      <register name="EDX"/>
    </pentry>
    <pentry minsize="1" maxsize="4">
      <register name="ECX"/>
    </pentry>
    <pentry minsize="1" maxsize="500" align="4">
      <addr offset="4" space="stack"/>
    </pentry>
  </input>
  <output killedbycall="true">
    <pentry minsize="4" maxsize="10" metatype="float" extension="float">
      <register name="ST0"/>
    </pentry>
    <pentry minsize="1" maxsize="4">
      <register name="EAX"/>
    </pentry>
    <pentry minsize="5" maxsize="8">
      <addr space="join" piece1="EDX" piece2="EAX"/>
    </pentry>
  </output>
  <unaffected>
    <varnode space="ram" offset="0" size="4"/>
    <register name="ESP"/>
    <register name="EBP"/>
    <register name="ESI"/>
    <register name="EDI"/>
    <register name="EBX"/>
    <register name="DF"/>
    <register name="FS_OFFSET"/>
  </unaffected>
  <killedbycall>
    <register name="ECX"/>
    <register name="EDX"/>
    <register name="ST0"/>
    <register name="ST1"/>
  </killedbycall>
  <likelytrash>
    <register name="ECX"/>
  </likelytrash>
</prototype>
""".strip()


def map_debug_call_type_to_ghidra(call_type: str) -> str:
    try:
        return _DEBUG_CALL_TYPE_TO_GHIDRA[call_type]
    except KeyError as e:
        raise ValueError(
            f"Unsupported debug calling convention for Ghidra import: {call_type!r}"
        ) from e


def normalize_x86_register_name(register: str) -> str:
    return _REGISTER_ALIASES.get(register.lower(), register.lower())


def registers_match(left: str, right: str) -> bool:
    return normalize_x86_register_name(left) == normalize_x86_register_name(right)


def _program_has_calling_convention(program, calling_convention: str) -> bool:
    compiler_spec = program.getCompilerSpec()
    models = compiler_spec.getAllModels()
    return any(model.getName() == calling_convention for model in models)


def ensure_borland_register_calling_convention(api):
    program = api.getCurrentProgram()
    if _program_has_calling_convention(program, BORLAND_REGISTER_CALL_TYPE):
        return

    try:
        # pylint: disable-next=import-outside-toplevel
        from ghidra.program.database import SpecExtension  # type: ignore[import-not-found]

        SpecExtension(program).addReplaceCompilerSpecExtension(
            _BORLAND_REGISTER_PROTOTYPE_XML,
            api.getMonitor(),
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        raise ReccmpGhidraException(
            f"Failed to install Ghidra calling convention {BORLAND_REGISTER_CALL_TYPE!r}"
        ) from e

    if not _program_has_calling_convention(program, BORLAND_REGISTER_CALL_TYPE):
        raise ReccmpGhidraException(
            f"Ghidra did not expose calling convention {BORLAND_REGISTER_CALL_TYPE!r} after installation"
        )
