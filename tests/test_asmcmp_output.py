from contextlib import redirect_stdout
import io

from reccmp.compare.diff import DiffReport, EntityCompareResult
from reccmp.tools.asmcmp import print_match_verbose
from reccmp.types import EntityType


def create_perfect_match() -> DiffReport:
    return DiffReport(
        match_type=EntityType.FUNCTION,
        orig_addr=0x1234,
        recomp_addr=0x5678,
        name="TestFunction",
        result=EntityCompareResult(match_ratio=1.0),
    )


def capture_verbose_output(match: DiffReport, encoding: str) -> str:
    output = io.BytesIO()
    stream = io.TextIOWrapper(output, encoding=encoding, errors="strict")

    with redirect_stdout(stream):
        print_match_verbose(match)

    stream.flush()
    return output.getvalue().decode(encoding)


def test_verbose_perfect_match_falls_back_to_ascii_for_cp1252_stdout():
    output = capture_verbose_output(create_perfect_match(), "cp1252")

    assert "TestFunction 100% match" in output
    assert "OK!" in output
    assert "✨" not in output


def test_verbose_perfect_match_keeps_unicode_marker_for_utf8_stdout():
    output = capture_verbose_output(create_perfect_match(), "utf-8")

    assert "TestFunction 100% match" in output
    assert "✨ OK! ✨" in output
