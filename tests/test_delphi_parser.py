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
