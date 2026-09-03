from textwrap import dedent

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
