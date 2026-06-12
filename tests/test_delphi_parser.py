from textwrap import dedent

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
    assert parser.functions[0].line_number == 6
    assert parser.functions[0].end_line == 11
