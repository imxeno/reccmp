from textwrap import dedent
from pathlib import PurePath

import pytest

from reccmp.parser.error import AlertCode
from reccmp.parser.delphi import DelphiParser


def test_delphi_function_range():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        interface

        implementation

        // FUNCTION: TEST 0x1000
        procedure TForm1.ButtonClick(Sender: TObject);
        var
          Value: Integer;
        begin
          Value := 1;
        end;
        """))

    assert len(parser.alerts) == 0
    assert len(parser.functions) == 1
    assert parser.functions[0].name == "Unit1.TForm1.ButtonClick"
    assert parser.functions[0].line_number == 8
    assert parser.functions[0].end_line == 13


def test_delphi_local_constants_before_function_body():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        implementation

        // FUNCTION: TEST 0x1000
        class function THash.SelfTest: Boolean;
        const
          // GLOBAL: TEST 0x2000
          Test1Out: array[0..1] of Byte = ($01, $02);
          // GLOBAL: TEST 0x3000
          Test2Out: array[0..1] of Byte = ($03, $04);
          // STRING: TEST 0x4000
          Greeting = 'local value';
        begin
          Result := Test1Out[0] <> Test2Out[0];
        end;
        """))

    assert len(parser.alerts) == 0
    assert len(parser.functions) == 1
    assert parser.functions[0].line_number == 6
    assert parser.functions[0].end_line == 16
    assert len(parser.variables) == 2
    assert [variable.name for variable in parser.variables] == [
        "Unit1.Test1Out",
        "Unit1.Test2Out",
    ]
    assert all(variable.is_static for variable in parser.variables)
    assert all(variable.parent_function == 0x1000 for variable in parser.variables)
    assert len(parser.strings) == 1
    assert parser.strings[0].name == "local value"


def test_delphi_nested_local_constant_uses_nested_parent():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        implementation

        // FUNCTION: TEST 0x1000
        procedure Outer;
          // NESTED: TEST 0x2000
          procedure Inner;
          const
            // GLOBAL: TEST 0x3000
            InnerValue: Integer = 1;
          begin
          end;
        begin
        end;
        """))

    assert len(parser.alerts) == 0
    assert len(parser.variables) == 1
    assert parser.variables[0].name == "Unit1.InnerValue"
    assert parser.variables[0].is_static is True
    assert parser.variables[0].parent_function == 0x2000


def test_delphi_rejects_unrelated_marker_before_function_body():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        implementation

        // FUNCTION: TEST 0x1000
        procedure Work;
          // VTABLE: TEST 0x2000
          TThing = class
          end;
        begin
        end;
        """))

    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.UNEXPECTED_MARKER
    assert len(parser.vtables) == 0


def test_delphi_global_and_string():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        interface

        var
          // GLOBAL: TEST 0x2000
          GlobalValue: Integer;

        resourcestring
          // STRING: TEST 0x3000
          Greeting = 'Don''t panic';
        """))

    assert len(parser.alerts) == 0
    assert len(parser.variables) == 1
    assert parser.variables[0].name == "Unit1.GlobalValue"
    assert len(parser.strings) == 1
    assert parser.strings[0].name == "Don't panic"


def test_delphi_vtable_marker_on_class():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        interface

        type
          // VTABLE: TEST 0x4000 TBaseForm
          TMainForm = class(TBaseForm)
          end;
        """))

    assert len(parser.alerts) == 0
    assert len(parser.vtables) == 1
    assert parser.vtables[0].name == "Unit1.TMainForm"
    assert parser.vtables[0].base_class == "TBaseForm"


def test_delphi_function_nameref():
    parser = DelphiParser()
    parser.read(dedent("""\
        // LIBRARY: TEST 0x5000 SYMBOL
        // @System@@LStrClr$qqrv
        """))

    assert len(parser.alerts) == 0
    assert len(parser.functions) == 1
    assert parser.functions[0].lookup_by_name is True
    assert parser.functions[0].name_is_symbol is True
    assert parser.functions[0].name == "@System@@LStrClr$qqrv"


def test_delphi_nested_routine_before_outer_body():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        implementation

        // FUNCTION: TEST 0x6000
        procedure Outer;
          procedure Inner;
          begin
          end;
        begin
        end;
        """))

    assert len(parser.alerts) == 0
    assert len(parser.functions) == 1
    assert parser.functions[0].line_number == 10
    assert parser.functions[0].end_line == 11


def test_delphi_multiple_nested_routines_before_outer_body():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        implementation

        // FUNCTION: TEST 0x7000
        function Outer: Boolean;
          function First: Boolean;
          begin
            Result := True;
          end;

          procedure Second;
          begin
          end;
        begin
          Result := First;
        end;
        """))

    assert len(parser.alerts) == 0
    assert len(parser.functions) == 1
    assert parser.functions[0].line_number == 15
    assert parser.functions[0].end_line == 17


def test_delphi_nested_routine_with_inner_blocks_before_outer_body():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        implementation

        // FUNCTION: TEST 0x8000
        procedure Outer;
          procedure Inner;
          var
            Value: record
              X: Integer;
            end;
          begin
            try
              case Value.X of
                0: Value.X := 1;
              end;
            finally
              Value.X := 2;
            end;
          end;
        begin
        end;
        """))

    assert len(parser.alerts) == 0
    assert len(parser.functions) == 1
    assert parser.functions[0].line_number == 21
    assert parser.functions[0].end_line == 22


def test_delphi_nested_marker_emits_local_function():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        implementation

        // FUNCTION: TEST 0x1000
        function Outer: Boolean;
          // NESTED: TEST 0x2000
          function Inner: Boolean;
          begin
            Result := False;
          end;
        begin
          Result := Inner;
        end;
        """))

    assert len(parser.alerts) == 0
    assert len(parser.functions) == 2
    functions = {function.offset: function for function in parser.functions}

    assert functions[0x1000].name == "Unit1.Outer"
    assert functions[0x1000].line_number == 12
    assert functions[0x1000].end_line == 14
    assert functions[0x2000].name == "Unit1.Inner"
    assert functions[0x2000].line_number == 8
    assert functions[0x2000].end_line == 11


def test_delphi_nested_marker_only_emits_marked_local_routine():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        implementation

        // FUNCTION: TEST 0x1000
        function Outer: Boolean;
          function First: Boolean;
          begin
            Result := True;
          end;

          // NESTED: TEST 0x3000
          procedure Second;
          begin
          end;
        begin
          Result := First;
        end;
        """))

    assert len(parser.alerts) == 0
    assert len(parser.functions) == 2
    functions = {function.offset: function for function in parser.functions}

    assert set(functions) == {0x1000, 0x3000}
    assert functions[0x3000].name == "Unit1.Second"
    assert functions[0x3000].line_number == 13
    assert functions[0x3000].end_line == 15


def test_delphi_misplaced_nested_marker_does_not_corrupt_outer_function():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;

        implementation

        // FUNCTION: TEST 0x1000
        procedure Outer;
        begin
          // NESTED: TEST 0x2000
          DoThing;
        end;
        """))

    assert len(parser.alerts) == 1
    assert parser.alerts[0].code == AlertCode.INCOMPATIBLE_MARKER
    assert len(parser.functions) == 1
    assert parser.functions[0].offset == 0x1000
    assert parser.functions[0].name == "Unit1.Outer"
    assert parser.functions[0].end_line == 10


def test_delphi_multilevel_nested_routines_and_siblings():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;
        // FUNCTION: TEST 0x1000
        procedure Outer;
          // NESTED: TEST 0x2000
          procedure Inner;
            // NESTED: TEST 0x3000
            procedure Deep;
              // NESTED: TEST 0x4000
              procedure Leaf;
              begin
                try
                  case 1 of
                    1: begin end;
                  end;
                finally
                end;
              end;
            begin
              Leaf;
            end;
            // NESTED: TEST 0x5000
            procedure DeepSibling; begin end;
          begin
            Deep;
          end;
          // NESTED: TEST 0x6000
          procedure InnerSibling;
          asm
            nop
          end;
        begin
          Inner;
        end;
        // FUNCTION: TEST 0x7000
        procedure Next; begin end;
        """))
    parser.finish()

    assert len(parser.alerts) == 0
    assert {
        function.offset: (function.name, function.line_number, function.end_line)
        for function in parser.functions
    } == {
        0x1000: ("Unit1.Outer", 31, 33),
        0x2000: ("Unit1.Inner", 23, 25),
        0x3000: ("Unit1.Deep", 18, 20),
        0x4000: ("Unit1.Leaf", 9, 17),
        0x5000: ("Unit1.DeepSibling", 22, 22),
        0x6000: ("Unit1.InnerSibling", 27, 30),
        0x7000: ("Unit1.Next", 35, 35),
    }


@pytest.mark.parametrize("mark_inner", [False, True])
def test_delphi_multilevel_local_constants_and_modules(mark_inner):
    source = dedent("""\
        // FUNCTION: TEST 0x1000
        // FUNCTION: OTHER 0x1100
        procedure Outer;
          // NESTED: TEST 0x2000
          // NESTED: OTHER 0x2100
          procedure Inner;
          const
            // GLOBAL: TEST 0x8000
            InnerValue: Integer = 1;
            // NESTED: TEST 0x3000
            // NESTED: OTHER 0x3100
            procedure Deep;
            const
              // GLOBAL: TEST 0x8001
              DeepValue: Integer = 2;
              // GLOBAL: OTHER 0x8101
              OtherValue: Integer = 3;
            begin
            end;
          begin
            // GLOBAL: TEST 0x8002
            InnerBodyValue := 4;
          end;
        begin
          // GLOBAL: TEST 0x8003
          OuterBodyValue := 5;
        end;
        """)
    if not mark_inner:
        source = source.replace("// NESTED: TEST 0x2000", "// Unmarked helper")
        source = source.replace("// NESTED: OTHER 0x2100", "// Unmarked helper")

    parser = DelphiParser()
    parser.read(source)
    parser.finish()

    assert len(parser.alerts) == 0
    functions = {
        (function.module, function.offset): (function.line_number, function.end_line)
        for function in parser.functions
    }
    expected = {
        ("TEST", 0x1000): (24, 27),
        ("OTHER", 0x1100): (24, 27),
        ("TEST", 0x3000): (12, 19),
        ("OTHER", 0x3100): (12, 19),
    }
    if mark_inner:
        expected.update({("TEST", 0x2000): (20, 23), ("OTHER", 0x2100): (20, 23)})
    assert functions == expected
    assert all(variable.is_static for variable in parser.variables)
    assert [variable.parent_function for variable in parser.variables] == [
        0x2000 if mark_inner else None,
        0x3000,
        0x3100,
        0x2000 if mark_inner else None,
        0x1000,
    ]


@pytest.mark.parametrize("marked", [False, True])
@pytest.mark.parametrize("separator", [" ", "\n"])
def test_delphi_nested_forward_does_not_consume_enclosing_body(marked, separator):
    parser = DelphiParser()
    marker = "// NESTED: TEST 0x3000" if marked else ""
    parser.read(dedent(f"""\
        // FUNCTION: TEST 0x1000
        procedure Outer;
          // NESTED: TEST 0x2000
          procedure Inner;
            {marker}
            procedure Forwarded;{separator}forward;
          begin
          end;
        begin
        end;
        """))
    parser.finish()

    assert [alert.code for alert in parser.alerts] == (
        [AlertCode.NO_IMPLEMENTATION] if marked else []
    )
    assert [(f.offset, f.line_number, f.end_line) for f in parser.functions] == [
        (0x2000, 4, 8 + separator.count("\n")),
        (0x1000, 9 + separator.count("\n"), 10 + separator.count("\n")),
    ]


def test_delphi_nested_forward_followed_by_implementation():
    parser = DelphiParser()
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1000
        procedure Outer;
          procedure Inner;
          forward;
          // NESTED: TEST 0x2000
          procedure Inner;
          begin
          end;
        begin
          Inner;
        end;
        """))
    parser.finish()

    assert len(parser.alerts) == 0
    assert [(f.offset, f.line_number, f.end_line) for f in parser.functions] == [
        (0x2000, 6, 8),
        (0x1000, 9, 11),
    ]


@pytest.mark.parametrize("opening,closing", [("(*", "*)"), ("{", "}")])
@pytest.mark.parametrize(
    "comment", ["procedure Example;", "begin", "// NESTED: TEST 0x3000"]
)
def test_delphi_nested_multiline_comments(opening, closing, comment):
    parser = DelphiParser()
    parser.read(dedent(f"""\
        // FUNCTION: TEST 0x1000
        procedure Outer;
          // NESTED: TEST 0x2000
          procedure Inner;
          {opening}
            {comment}
          {closing}
          begin
            {opening}
              end;
            {closing}
          end;
        begin
        end;
        """))
    parser.finish()

    assert len(parser.alerts) == 0
    assert [(f.offset, f.line_number, f.end_line) for f in parser.functions] == [
        (0x2000, 4, 12),
        (0x1000, 13, 14),
    ]


def test_delphi_comments_preserve_strings_and_code_after_closing_delimiter():
    parser = DelphiParser()
    parser.read(dedent("""\
        unit Unit1;
        // FUNCTION: TEST 0x1000
        procedure Outer;
          // Comment delimiters in line comments are ignored: { (*
          // NESTED: TEST 0x2000
          procedure Inner; (* declaration comment
            procedure Example;
          *)
          const
            // STRING: TEST 0x3000
            Text = 'Don''t strip { (* // } *)';
          (* body comment
            begin
          *) begin
          end;
        begin
        end;
        """))
    parser.finish()

    assert len(parser.alerts) == 0
    assert len(parser.strings) == 1
    assert parser.strings[0].name == "Don't strip { (* // } *)"
    assert [(f.offset, f.line_number, f.end_line) for f in parser.functions] == [
        (0x2000, 6, 15),
        (0x1000, 16, 17),
    ]


@pytest.mark.parametrize("opening", ["(*", "{"])
def test_delphi_reset_clears_block_comment_state(opening):
    parser = DelphiParser()
    parser.read(opening + "\n")
    parser.reset_and_set_filename(PurePath("next.pas"))
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1000
        procedure Next;
        begin
        end;
        """))
    parser.finish()

    assert len(parser.alerts) == 0
    assert [(f.offset, f.line_number, f.end_line) for f in parser.functions] == [
        (0x1000, 2, 4),
    ]


def test_delphi_misplaced_nested_marker_in_deep_body():
    parser = DelphiParser()
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1000
        procedure Outer;
          // NESTED: TEST 0x2000
          procedure Inner;
            // NESTED: TEST 0x3000
            procedure Deep;
            begin
              // NESTED: TEST 0x4000
              DoThing;
            end;
          begin
          end;
        begin
        end;
        """))
    parser.finish()

    assert [alert.code for alert in parser.alerts] == [AlertCode.INCOMPATIBLE_MARKER]
    assert [(f.offset, f.end_line) for f in parser.functions] == [
        (0x3000, 10),
        (0x2000, 12),
        (0x1000, 14),
    ]


@pytest.mark.parametrize("reset", [False, True])
def test_delphi_nested_state_cleared_after_recovery_or_reset(reset):
    parser = DelphiParser()
    parser.read(dedent("""\
        // FUNCTION: TEST 0x1000
        procedure Outer;
          // NESTED: TEST 0x2000
          procedure Inner;
            // NESTED: TEST 0x3000
            procedure Deep;
              // NESTED: TEST 0x4000
        """))
    if reset:
        parser.reset_and_set_filename(PurePath("next.pas"))
    else:
        parser.read("// VTABLE: TEST 0x5000\n")
        assert [alert.code for alert in parser.alerts] == [AlertCode.UNEXPECTED_MARKER]

    parser.read(dedent("""\
        // FUNCTION: TEST 0x6000
        procedure Next;
          procedure Unmarked;
          begin
          end;
        begin
        end;
        """))
    parser.finish()

    assert len(parser.functions) == 1
    assert parser.functions[0].offset == 0x6000
    assert parser.functions[0].end_line == parser.line_number
    assert len(parser.alerts) == (0 if reset else 1)
