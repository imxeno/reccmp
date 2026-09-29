"""Delphi/Object Pascal source parser for reccmp annotations."""

import io
import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Iterator

from .error import AlertCode, ParserAlert
from .marker import (
    DecompMarker,
    MarkerCategory,
    ProjectAliases,
    is_marker_exact,
    match_marker,
)
from .node import (
    ParserFunction,
    ParserLineSymbol,
    ParserString,
    ParserSymbol,
    ParserVariable,
    ParserVtable,
)
from .parser import MarkerDict, ReccmpParserResult, ReaderState
from .util import ParserCodeString, get_synthetic_name

_unit_decl_regex = re.compile(
    r"^\s*(?:unit|program|library|package)\s+(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;",
    flags=re.I,
)

_routine_decl_regex = re.compile(
    r"""
    ^\s*
    (?:(?:class|static)\s+)?
    (?P<kind>procedure|function|constructor|destructor|operator)\s+
    (?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|[^\s(;:]+)
    """,
    flags=re.I | re.X,
)

_class_decl_regex = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z_]\w*)
    \s*=\s*
    (?:(?:packed|abstract|sealed)\s+)*
    (?P<kind>class|object)
    (?:\s*\(\s*(?P<base>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\))?
    """,
    flags=re.I | re.X,
)

_variable_decl_regex = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)
    (?:\s*,\s*[A-Za-z_]\w*)*
    \s*(?::|=)
    """,
    flags=re.I | re.X,
)

_block_word_regex = re.compile(
    r"\b(begin|case|record|class|object|try|asm|end)\b", re.I
)

_comment_token_regex = re.compile(r"'(?:[^']|'')*'|//[^\r\n]*|\{|\(\*")

_conditional_token_regex = re.compile(
    r"//[^\r\n]*|'(?:''|[^'\r\n])*'|\(\*.*?\*\)"
    r"|\{\$(?P<directive>IFDEF|IFNDEF|IFOPT|IFEND|IF|ELSE|ENDIF)\b[ \t]*(?P<arg>[^}]*)\}"
    r"|\{[^}]*\}",
    flags=re.I | re.S,
)


def blank_inactive_conditionals(text: str, defines: dict[str, bool]) -> str:
    """Return ``text`` with the conditional branches a build with ``defines`` does not
    compile replaced by spaces. Line breaks are kept, so line numbers and columns stay
    those of the file (and of the compiler's line table). Only {$IFDEF}/{$IFNDEF} on a
    symbol listed in ``defines`` are decided; every other conditional ({$IF}, {$IFOPT},
    symbols from the compiler or include files) keeps both branches. The directives
    themselves stay: the parser reads them as comments."""

    values = {name.upper(): bool(value) for name, value in defines.items()}
    frames: list[bool | None] = (
        []
    )  # per open conditional: branch compiled, or None if undecided
    out: list[str] = []
    position = 0

    def blank(segment: str) -> str:
        if any(frame is False for frame in frames):
            return re.sub(r"[^\r\n]", " ", segment)
        return segment

    for match in _conditional_token_regex.finditer(text):
        out.append(blank(text[position : match.start()]))
        position = match.end()
        directive = (match.group("directive") or "").upper()
        if not directive:
            out.append(blank(match.group(0)))
            continue
        out.append(match.group(0))
        symbol = (match.group("arg").split() or [""])[0].upper()
        if directive in ("IFDEF", "IFNDEF"):
            value = values.get(symbol)
            frames.append(None if value is None else value == (directive == "IFDEF"))
        elif directive in ("IF", "IFOPT"):
            frames.append(None)
        elif directive == "ELSE":
            if frames and frames[-1] is not None:
                frames[-1] = not frames[-1]
        elif frames:  # ENDIF / IFEND
            frames.pop()
    out.append(blank(text[position:]))
    return "".join(out)


def _strip_pascal_block_comments(
    line: str, comment_end: str | None
) -> tuple[str, str | None]:
    """Remove block comments while preserving literals and annotation comments."""
    result = []
    pos = 0
    while pos < len(line):
        if comment_end is not None:
            end = line.find(comment_end, pos)
            if end == -1:
                break
            pos = end + len(comment_end)
            comment_end = None
        elif (match := _comment_token_regex.search(line, pos)) is not None:
            result.append(line[pos : match.start()])
            token = match.group()
            if token in ("{", "(*"):
                comment_end = "}" if token == "{" else "*)"
                result.append(" ")
            else:
                result.append(token)
            pos = match.end()
        else:
            result.append(line[pos:])
            break

    return "".join(result), comment_end


def _strip_pascal_comments_and_strings(line: str) -> str:
    """Remove comments and quoted strings from a single Pascal source line."""

    result = []
    i = 0
    in_string = False
    while i < len(line):
        ch = line[i]

        if in_string:
            if ch == "'":
                # Doubled single quote inside a Pascal string literal.
                if i + 1 < len(line) and line[i + 1] == "'":
                    i += 2
                    continue
                in_string = False
            i += 1
            continue

        if ch == "'":
            in_string = True
            result.append("''")
            i += 1
            continue

        if line.startswith("//", i):
            break

        if ch == "{":
            end = line.find("}", i + 1)
            if end == -1:
                break
            i = end + 1
            continue

        if line.startswith("(*", i):
            end = line.find("*)", i + 2)
            if end == -1:
                break
            i = end + 2
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def _get_pascal_string_contents(line: str) -> ParserCodeString | None:
    """Return the first Pascal single-quoted string literal on the line."""

    i = 0
    while i < len(line):
        if line[i] != "'":
            i += 1
            continue

        i += 1
        text = []
        while i < len(line):
            ch = line[i]
            if ch == "'":
                if i + 1 < len(line) and line[i + 1] == "'":
                    text.append("'")
                    i += 2
                    continue

                is_widechar = bool(re.search(r"\b(WideString|PWideChar)\b", line, re.I))
                return ParserCodeString(text="".join(text), is_widechar=is_widechar)

            text.append(ch)
            i += 1

        return None

    return None


def _get_pascal_variable_name(line: str) -> str | None:
    match = _variable_decl_regex.match(_strip_pascal_comments_and_strings(line))
    if match is not None:
        return match.group("name")

    return None


def _has_no_implementation(line: str) -> bool:
    sanitized = _strip_pascal_comments_and_strings(line).lower()
    return re.search(r"(?:^|;)\s*(?:forward\s*;|external\b)", sanitized) is not None


@dataclass
class _NestedRoutine:
    """Declaration and body state for one local routine, marked or unmarked."""

    markers: MarkerDict
    start: int
    name: str
    body_depth: int = 0
    has_nested_routines: bool = False


class DelphiParser:
    """Parse reccmp annotations from Delphi/Object Pascal source files."""

    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        aliases: ProjectAliases | None = None,
        defines: dict[str, bool] | None = None,
    ) -> None:
        self._symbols: list[ParserSymbol] = []
        self.alerts: list[ParserAlert] = []
        self.line_number = 0
        self.state = ReaderState.SEARCH
        self.last_line = ""
        self.filename: PurePath = PurePath("")
        self.aliases = aliases or {}
        # Conditional symbols of the build: see blank_inactive_conditionals.
        self.defines = dict(defines or {})

        self.fun_markers = MarkerDict()
        self.nested_fun_markers = MarkerDict()
        self.var_markers = MarkerDict()
        self.tbl_markers = MarkerDict()

        self.function_start = 0
        self.function_sig = ""
        self.function_body_depth = 0
        self.unit_name: str | None = None
        self._resume_state_after_variable: ReaderState | None = None

        self._nested_routines: list[_NestedRoutine] = []
        self._nested_routine_seen = False
        self._comment_end: str | None = None

    def reset_and_set_filename(self, filename: PurePath):
        self._symbols = []
        self.alerts = []
        self.line_number = 0
        self.state = ReaderState.SEARCH
        self.last_line = ""
        self.filename = filename

        self.fun_markers.empty()
        self.nested_fun_markers.empty()
        self.var_markers.empty()
        self.tbl_markers.empty()

        self.function_start = 0
        self.function_sig = ""
        self.function_body_depth = 0
        self.unit_name = None
        self._resume_state_after_variable = None
        self._nested_routines.clear()
        self._nested_routine_seen = False
        self._comment_end = None

    @property
    def functions(self) -> list[ParserFunction]:
        return [s for s in self._symbols if isinstance(s, ParserFunction)]

    @property
    def vtables(self) -> list[ParserVtable]:
        return [s for s in self._symbols if isinstance(s, ParserVtable)]

    @property
    def variables(self) -> list[ParserVariable]:
        return [s for s in self._symbols if isinstance(s, ParserVariable)]

    @property
    def strings(self) -> list[ParserString]:
        return [s for s in self._symbols if isinstance(s, ParserString)]

    def iter_symbols(self, module: str | None = None) -> Iterator[ParserSymbol]:
        for s in self._symbols:
            if module is None or s.module == module:
                yield s

    def _recover(self):
        self.state = ReaderState.SEARCH
        self.fun_markers.empty()
        self.nested_fun_markers.empty()
        self.var_markers.empty()
        self.tbl_markers.empty()
        self.function_body_depth = 0
        self._resume_state_after_variable = None
        self._nested_routines.clear()
        self._nested_routine_seen = False

    def _syntax_warning(self, code: AlertCode):
        self.alerts.append(
            ParserAlert(
                path=self.filename,
                line_number=self.line_number,
                code=code,
                detail=self.last_line.strip(),
            )
        )

    def _syntax_error(self, code: AlertCode):
        self._syntax_warning(code)
        self._recover()

    def _qualify_name(self, name: str) -> str:
        if self.unit_name is None:
            return name

        if name == self.unit_name or name.startswith(f"{self.unit_name}."):
            return name

        return f"{self.unit_name}.{name}"

    def _function_marker(self, marker: DecompMarker):
        if self.fun_markers.insert(marker):
            self._syntax_warning(AlertCode.DUPLICATE_MODULE)
        self.state = ReaderState.WANT_SIG

    def _nested_function_marker(self, marker: DecompMarker):
        if self.nested_fun_markers.insert(marker):
            self._syntax_warning(AlertCode.DUPLICATE_MODULE)

    def _nameref_marker(self, marker: DecompMarker):
        if self.fun_markers.insert(marker):
            self._syntax_warning(AlertCode.DUPLICATE_MODULE)

        if marker.is_template():
            self.state = ReaderState.IN_TEMPLATE
        elif marker.is_synthetic():
            self.state = ReaderState.IN_SYNTHETIC
        else:
            self.state = ReaderState.IN_LIBRARY

    def _append_function_symbols(
        self,
        markers: MarkerDict,
        line_number: int,
        name: str,
        end_line: int,
        lookup_by_name: bool = False,
    ):  # pylint: disable=too-many-positional-arguments
        for marker in markers.iter():
            name_is_symbol = (
                marker.extra is not None and marker.extra.lower() == "symbol"
            )
            if name_is_symbol and not lookup_by_name:
                self._syntax_warning(AlertCode.SYMBOL_OPTION_IGNORED)
                name_is_symbol = False

            is_folded = marker.extra is not None and marker.extra.lower() == "folded"

            self._symbols.append(
                ParserFunction(
                    type=marker.type,
                    line_number=line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=name,
                    filename=self.filename,
                    lookup_by_name=lookup_by_name,
                    name_is_symbol=name_is_symbol,
                    end_line=end_line,
                    is_folded=is_folded,
                )
            )

    def _function_done(self, lookup_by_name: bool = False, unexpected: bool = False):
        end_line = self.line_number - 1 if unexpected else self.line_number
        self._append_function_symbols(
            self.fun_markers,
            self.function_start,
            self.function_sig,
            end_line,
            lookup_by_name,
        )

        self.fun_markers.empty()
        self.function_body_depth = 0
        self.state = ReaderState.SEARCH
        self.nested_fun_markers.empty()
        self._nested_routines.clear()
        self._nested_routine_seen = False

    def _nested_function_done(self):
        routine = self._nested_routines.pop()
        self._append_function_symbols(
            routine.markers,
            routine.start,
            routine.name,
            self.line_number,
        )

    def _vtable_marker(self, marker: DecompMarker):
        if self.tbl_markers.insert(marker):
            self._syntax_warning(AlertCode.DUPLICATE_MODULE)
        self.state = ReaderState.IN_VTABLE

    def _vtable_done(self, class_name: str, declared_base: str | None):
        for marker in self.tbl_markers.iter():
            self._symbols.append(
                ParserVtable(
                    type=marker.type,
                    line_number=self.line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=self._qualify_name(class_name),
                    filename=self.filename,
                    base_class=marker.extra or declared_base,
                )
            )

        self.tbl_markers.empty()
        self.state = ReaderState.SEARCH

    def _variable_marker(self, marker: DecompMarker):
        if self.var_markers.insert(marker):
            self._syntax_warning(AlertCode.DUPLICATE_MODULE)

        if self.state in (
            ReaderState.WANT_CURLY,
            ReaderState.IN_FUNC,
            ReaderState.IN_FUNC_GLOBAL,
        ):
            self._resume_state_after_variable = self.state
            self.state = ReaderState.IN_FUNC_GLOBAL
        else:
            self._resume_state_after_variable = None
            self.state = ReaderState.IN_GLOBAL

    def _variable_done(
        self, variable_name: str | None = None, string: ParserCodeString | None = None
    ):
        if variable_name is None and string is None:
            self._syntax_error(AlertCode.NO_SUITABLE_NAME)
            return

        for marker in self.var_markers.iter():
            if marker.is_string():
                assert string is not None
                self._symbols.append(
                    ParserString(
                        type=marker.type,
                        line_number=self.line_number,
                        module=marker.module,
                        offset=marker.offset,
                        name=string.text,
                        filename=self.filename,
                        is_widechar=string.is_widechar,
                    )
                )
            else:
                parent_function = None
                is_static = self._resume_state_after_variable in (
                    ReaderState.WANT_CURLY,
                    ReaderState.IN_FUNC,
                )

                if is_static:
                    markers = (
                        self._nested_routines[-1].markers
                        if self._nested_routines
                        else self.fun_markers
                    )
                    fun_marker = markers.query(MarkerCategory.FUNCTION, marker.module)
                    if fun_marker is not None:
                        parent_function = fun_marker.offset

                assert variable_name is not None
                self._symbols.append(
                    ParserVariable(
                        type=marker.type,
                        line_number=self.line_number,
                        module=marker.module,
                        offset=marker.offset,
                        name=self._qualify_name(variable_name),
                        filename=self.filename,
                        is_static=is_static,
                        parent_function=parent_function,
                    )
                )

        self.var_markers.empty()
        if self._resume_state_after_variable is not None:
            self.state = self._resume_state_after_variable
        else:
            self.state = ReaderState.SEARCH
        self._resume_state_after_variable = None

    def _line_marker(self, marker: DecompMarker):
        self._symbols.append(
            ParserLineSymbol(
                type=marker.type,
                line_number=self.line_number,
                module=marker.module,
                offset=marker.offset,
                name=f"{self.filename.name}:{self.line_number}",
                filename=self.filename,
            )
        )

    def _has_nested_function_marker(self) -> bool:
        return next(self.nested_fun_markers.iter(), None) is not None

    def _handle_marker(self, marker: DecompMarker):
        if marker.is_nested_function():
            if self.state == ReaderState.WANT_CURLY and not (
                self._nested_routines and self._nested_routines[-1].body_depth > 0
            ):
                self._nested_function_marker(marker)
            else:
                self._syntax_warning(AlertCode.INCOMPATIBLE_MARKER)
            return

        if self.state == ReaderState.WANT_CURLY:
            if marker.is_string() or marker.is_variable():
                self._variable_marker(marker)
            else:
                self._syntax_error(AlertCode.UNEXPECTED_MARKER)
            return

        if self.state == ReaderState.IN_FUNC and not marker.allowed_in_func():
            self._syntax_warning(AlertCode.MISSED_END_OF_FUNCTION)
            self._function_done(unexpected=True)

        if marker.is_regular_function():
            if self.state in (ReaderState.SEARCH, ReaderState.WANT_SIG):
                self._function_marker(marker)
            else:
                self._syntax_error(AlertCode.INCOMPATIBLE_MARKER)

        elif marker.is_template():
            if self.state in (ReaderState.SEARCH, ReaderState.IN_TEMPLATE):
                self._nameref_marker(marker)
            else:
                self._syntax_error(AlertCode.INCOMPATIBLE_MARKER)

        elif marker.is_synthetic():
            if self.state in (ReaderState.SEARCH, ReaderState.IN_SYNTHETIC):
                self._nameref_marker(marker)
            else:
                self._syntax_error(AlertCode.INCOMPATIBLE_MARKER)

        elif marker.is_library():
            if self.state in (ReaderState.SEARCH, ReaderState.IN_LIBRARY):
                self._nameref_marker(marker)
            else:
                self._syntax_error(AlertCode.INCOMPATIBLE_MARKER)

        elif marker.is_string() or marker.is_variable():
            if self.state in (
                ReaderState.SEARCH,
                ReaderState.IN_GLOBAL,
                ReaderState.IN_FUNC,
                ReaderState.IN_FUNC_GLOBAL,
            ):
                self._variable_marker(marker)
            else:
                self._syntax_error(AlertCode.INCOMPATIBLE_MARKER)

        elif marker.is_vtable():
            if self.state in (ReaderState.SEARCH, ReaderState.IN_VTABLE):
                self._vtable_marker(marker)
            else:
                self._syntax_error(AlertCode.INCOMPATIBLE_MARKER)

        elif marker.is_line():
            self._line_marker(marker)

        else:
            self._syntax_warning(AlertCode.UNKNOWN_ANNOTATION)

    def _block_delta(self, line: str) -> int:
        delta = 0
        sanitized = _strip_pascal_comments_and_strings(line)
        for match in _block_word_regex.finditer(sanitized):
            word = match.group(1).lower()
            if word == "end":
                delta -= 1
            else:
                delta += 1
        return delta

    def _has_block_start(self, line: str) -> bool:
        sanitized = _strip_pascal_comments_and_strings(line)
        return re.search(r"\b(begin|asm)\b", sanitized, flags=re.I) is not None

    def _start_or_update_function_body(self, line: str):
        if not self._has_block_start(line):
            self.state = ReaderState.WANT_CURLY
            return

        self.state = ReaderState.IN_FUNC
        self.function_body_depth = 0
        self._update_function_body(line)

    def _update_function_body(self, line: str):
        self.function_body_depth += self._block_delta(line)
        if self.function_body_depth <= 0:
            self._function_done()

    def _update_waiting_for_outer_body(self, line: str):
        routine = self._nested_routines[-1] if self._nested_routines else None
        if routine is not None and routine.body_depth > 0:
            routine.body_depth += self._block_delta(line)
            if routine.body_depth <= 0:
                self._nested_function_done()
            return

        sanitized = _strip_pascal_comments_and_strings(line)
        if (match := _routine_decl_regex.match(sanitized)) is not None:
            if _has_no_implementation(line):
                if self._has_nested_function_marker():
                    self._syntax_warning(AlertCode.NO_IMPLEMENTATION)
                self.nested_fun_markers.empty()
                return

            routine = _NestedRoutine(
                markers=self.nested_fun_markers,
                start=self.line_number,
                name=self._qualify_name(match.group("name")),
            )
            self._nested_routines.append(routine)
            self.nested_fun_markers = MarkerDict()
        elif routine is not None and _has_no_implementation(line):
            if next(routine.markers.iter(), None) is not None:
                self._syntax_warning(AlertCode.NO_IMPLEMENTATION)
            self._nested_routines.pop()
            return

        if self._has_nested_function_marker() and sanitized.strip():
            self._syntax_warning(AlertCode.INCOMPATIBLE_MARKER)
            self.nested_fun_markers.empty()

        if self._has_block_start(line):
            if routine is not None:
                # Count implemented children only; forward declarations have no range.
                if len(self._nested_routines) > 1:
                    self._nested_routines[-2].has_nested_routines = True
                else:
                    self._nested_routine_seen = True
                if routine.has_nested_routines:
                    routine.start = self.line_number
                routine.body_depth = self._block_delta(line)
                if routine.body_depth <= 0:
                    self._nested_function_done()
            else:
                if self._nested_routine_seen:
                    self.function_start = self.line_number
                self._start_or_update_function_body(line)

    def read_line(self, line: str):
        if self.state == ReaderState.DONE:
            return

        self.last_line = line
        self.line_number += 1

        in_comment = self._comment_end is not None
        line, self._comment_end = _strip_pascal_block_comments(line, self._comment_end)
        if not line.strip() and (in_comment or self.last_line.strip()):
            return

        marker = match_marker(line, aliases=self.aliases)
        if marker is not None:
            if not is_marker_exact(self.last_line):
                self._syntax_warning(AlertCode.NOT_STRICT_FORMAT)
            self._handle_marker(marker)
            return

        sanitized = _strip_pascal_comments_and_strings(line)
        line_strip = sanitized.strip()

        if (
            self.unit_name is None
            and (match := _unit_decl_regex.match(line)) is not None
        ):
            self.unit_name = match.group("name")

        if self.state in (
            ReaderState.IN_SYNTHETIC,
            ReaderState.IN_TEMPLATE,
            ReaderState.IN_LIBRARY,
        ):
            name = get_synthetic_name(line)
            if name is None:
                self._syntax_error(AlertCode.BAD_NAMEREF)
            else:
                self.function_sig = name
                self.function_start = self.line_number
                self._function_done(lookup_by_name=True)

        elif self.state == ReaderState.WANT_SIG:
            if len(line_strip) == 0:
                self._syntax_warning(AlertCode.UNEXPECTED_BLANK_LINE)

            elif line.lstrip().startswith("//"):
                synthetic_name = get_synthetic_name(line)
                assert synthetic_name is not None
                self.function_sig = synthetic_name
                self.function_start = self.line_number
                self._function_done(lookup_by_name=True)

            elif (match := _routine_decl_regex.match(sanitized)) is not None:
                self.function_sig = self._qualify_name(match.group("name"))
                self.function_start = self.line_number
                if _has_no_implementation(line):
                    self._syntax_error(AlertCode.NO_IMPLEMENTATION)
                else:
                    self._start_or_update_function_body(line)

            else:
                self._syntax_error(AlertCode.MISSED_START_OF_FUNCTION)

        elif self.state == ReaderState.WANT_CURLY:
            self._update_waiting_for_outer_body(line)

        elif self.state == ReaderState.IN_FUNC:
            self._update_function_body(line)

        elif self.state in (ReaderState.IN_GLOBAL, ReaderState.IN_FUNC_GLOBAL):
            if len(line_strip) == 0:
                self._syntax_warning(AlertCode.UNEXPECTED_BLANK_LINE)
                return

            global_markers_queued = any(
                m.is_variable() for m in self.var_markers.iter()
            )
            variable_name = (
                _get_pascal_variable_name(line) if global_markers_queued else None
            )
            string = _get_pascal_string_contents(line)
            self._variable_done(variable_name, string)

        elif self.state == ReaderState.IN_VTABLE:
            if (match := _class_decl_regex.match(sanitized)) is not None:
                self._vtable_done(match.group("name"), match.group("base"))

    def read(self, text: str):
        if self.defines:
            text = blank_inactive_conditionals(text, self.defines)
        for line in io.StringIO(text, newline=None):
            self.read_line(line)

    def finish(self):
        if self.state != ReaderState.SEARCH:
            self._syntax_warning(AlertCode.UNEXPECTED_END_OF_FILE)

        self.state = ReaderState.DONE

    def to_result(self) -> ReccmpParserResult:
        return ReccmpParserResult(
            tuple(self._symbols), tuple(self.alerts), self.filename
        )
