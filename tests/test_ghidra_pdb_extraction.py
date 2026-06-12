from unittest.mock import Mock

import pytest

# pylint: disable=protected-access

from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey
from reccmp.cvdump.symbols import StackOrRegisterSymbol, SymbolsEntry
from reccmp.cvdump.types import CvdumpTypesParser
from reccmp.ghidra.importer.calling_conventions import (
    BORLAND_REGISTER_CALL_TYPE,
    map_debug_call_type_to_ghidra,
    registers_match,
)
from reccmp.ghidra.importer.pdb_extraction import (
    CppRegisterSymbol,
    PdbFunctionExtractor,
)


def test_debug_call_type_mapping_includes_delphi_conventions():
    assert map_debug_call_type_to_ghidra("Near C") == "__cdecl"
    assert map_debug_call_type_to_ghidra("Near Std") == "__stdcall"
    assert map_debug_call_type_to_ghidra("Near Fast") == "__fastcall"
    assert map_debug_call_type_to_ghidra("ThisCall") == "__thiscall"
    assert (
        map_debug_call_type_to_ghidra("Borland Register") == BORLAND_REGISTER_CALL_TYPE
    )


def test_debug_call_type_mapping_rejects_pascal_until_it_has_a_ghidra_model():
    with pytest.raises(ValueError, match="Near Pascal"):
        map_debug_call_type_to_ghidra("Near Pascal")


def test_register_alias_matching_uses_32_bit_parent_registers():
    assert registers_match("al", "EAX")
    assert registers_match("dh", "edx")
    assert registers_match("si", "ESI")
    assert not registers_match("al", "EDX")


def _extractor_with_borland_register_method() -> PdbFunctionExtractor:
    types = CvdumpTypesParser()
    arg_list_type = CvdumpTypeKey(0x1000)
    method_type = CvdumpTypeKey(0x1001)
    types.keys[arg_list_type] = {
        "type": "LF_ARGLIST",
        "argcount": 1,
        "args": [CVInfoTypeEnum.T_INT4],
    }
    types.keys[method_type] = {
        "type": "LF_MFUNCTION",
        "return_type": CVInfoTypeEnum.T_VOID,
        "class_type": CvdumpTypeKey(0x2000),
        "this_type": CVInfoTypeEnum.T_32PVOID,
        "call_type": "Borland Register",
        "func_attr": "",
        "num_params": 1,
        "arg_list_type": arg_list_type,
        "this_adjust": 0,
    }
    compare = Mock()
    compare.types = types
    return PdbFunctionExtractor(compare)


def test_borland_register_method_signature_synthesizes_self():
    extractor = _extractor_with_borland_register_method()
    symbol = SymbolsEntry(
        type="S_GPROC32",
        section=1,
        offset=0x1000,
        size=0x20,
        func_type=CvdumpTypeKey(0x1001),
        name="Unit1.TWidget.Click",
        symbols=[
            StackOrRegisterSymbol(
                "S_REGISTER",
                "edx",
                CVInfoTypeEnum.T_INT4,
                "Value",
            )
        ],
    )

    signature = extractor._get_func_signature(symbol)

    assert signature is not None
    assert signature.call_type == BORLAND_REGISTER_CALL_TYPE
    assert signature.arglist == [CVInfoTypeEnum.T_32PVOID, CVInfoTypeEnum.T_INT4]
    assert (
        CppRegisterSymbol("Self", CVInfoTypeEnum.T_32PVOID, "eax") in signature.symbols
    )
    assert CppRegisterSymbol("Value", CVInfoTypeEnum.T_INT4, "edx") in signature.symbols
    assert extractor.compare.types.keys[CvdumpTypeKey(0x1000)]["args"] == [
        CVInfoTypeEnum.T_INT4
    ]


def test_borland_register_method_signature_reuses_emitted_self():
    extractor = _extractor_with_borland_register_method()
    symbol = SymbolsEntry(
        type="S_GPROC32",
        section=1,
        offset=0x1000,
        size=0x20,
        func_type=CvdumpTypeKey(0x1001),
        name="Unit1.TWidget.Click",
        symbols=[
            StackOrRegisterSymbol(
                "S_REGISTER",
                "EAX",
                CVInfoTypeEnum.T_32PVOID,
                "Self",
            )
        ],
    )

    signature = extractor._get_func_signature(symbol)

    assert signature is not None
    assert (
        signature.symbols.count(
            CppRegisterSymbol("Self", CVInfoTypeEnum.T_32PVOID, "eax")
        )
        == 1
    )
