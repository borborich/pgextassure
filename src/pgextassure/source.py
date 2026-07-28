"""Lexical helpers that preserve offsets while removing scanner noise."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterator


_RUST_RAW_STRING_START = re.compile(r'r(#{0,255})"')
_RUST_CHAR_LITERAL = re.compile(
    r"""'(?:\\(?:[nrt0\\'"]|x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,6}\})|[^\\'\r\n])'"""
)
_SQL_DOLLAR_DELIMITER = re.compile(
    r"\$(?:[A-Za-z_]|[^\x00-\x7f])"
    r"(?:[A-Za-z0-9_]|[^\x00-\x7f])*\$|\$\$"
)
_PSQL_COPY_COMMAND = re.compile(r"\\copy\b", re.IGNORECASE)


def _is_sql_identifier_continuation(character: str) -> bool:
    """Approximate PostgreSQL's unquoted identifier continuation class."""

    return (
        character.isalnum()
        or character in {"_", "$"}
        or ord(character) >= 0x80
    )


def _sql_dollar_delimiter_at(text: str, index: int) -> re.Match[str] | None:
    """Match an opening dollar quote that is not embedded in an identifier."""

    if index > 0 and _is_sql_identifier_continuation(text[index - 1]):
        return None
    return _SQL_DOLLAR_DELIMITER.match(text, index)


def _find_line_break(text: str, start: int) -> int:
    """Return the next CR/LF offset, or ``len(text)`` when none remains."""

    carriage_return = text.find("\r", start)
    line_feed = text.find("\n", start)
    if carriage_return < 0:
        return len(text) if line_feed < 0 else line_feed
    if line_feed < 0:
        return carriage_return
    return min(carriage_return, line_feed)


def _line_break_end(text: str, index: int) -> int | None:
    """Return the offset after one CR, LF, or CRLF sequence at ``index``."""

    if text[index] == "\n":
        return index + 1
    if text[index] == "\r":
        if index + 1 < len(text) and text[index + 1] == "\n":
            return index + 2
        return index + 1
    return None


def canonical_json_bytes(value: Any) -> bytes:
    """Encode a JSON-compatible value canonically for stable hashes."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def one_based_line(text: str, offset: int) -> int:
    end = max(offset, 0)
    return (
        text.count("\r", 0, end)
        + text.count("\n", 0, end)
        - text.count("\r\n", 0, end)
        + 1
    )


def evidence_line(text: str, offset: int, limit: int = 240) -> str:
    bounded_offset = max(offset, 0)
    previous_cr = text.rfind("\r", 0, bounded_offset)
    previous_lf = text.rfind("\n", 0, bounded_offset)
    line_start = max(previous_cr, previous_lf) + 1
    line_end = _find_line_break(text, bounded_offset)
    value = " ".join(text[line_start:line_end].strip().split())
    if len(value) > limit:
        return value[: limit - 1] + "…"
    return value


def _blank(buffer: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if buffer[index] not in {"\r", "\n"}:
            buffer[index] = " "


def mask_c_like(text: str, *, rust: bool = False) -> str:
    """Mask comments and literals in C/Rust while retaining length/newlines."""

    result = list(text)
    length = len(text)
    index = 0
    while index < length:
        if text.startswith("//", index):
            end = _find_line_break(text, index + 2)
            _blank(result, index, end)
            index = end
            continue
        if text.startswith("/*", index):
            if rust:
                depth = 1
                cursor = index + 2
                while cursor < length and depth:
                    if text.startswith("/*", cursor):
                        depth += 1
                        cursor += 2
                    elif text.startswith("*/", cursor):
                        depth -= 1
                        cursor += 2
                    else:
                        cursor += 1
                end = cursor
            else:
                end_marker = text.find("*/", index + 2)
                end = length if end_marker < 0 else end_marker + 2
            _blank(result, index, end)
            index = end
            continue

        if rust and text[index] == "r":
            raw = _RUST_RAW_STRING_START.match(text, index)
            if raw:
                hashes = raw.group(1)
                delimiter = '"' + hashes
                end_marker = text.find(delimiter, index + len(raw.group(0)))
                end = length if end_marker < 0 else end_marker + len(delimiter)
                _blank(result, index, end)
                index = end
                continue

        quote = text[index]
        if quote in {'"', "'"}:
            start = index
            if rust and quote == "'":
                character = _RUST_CHAR_LITERAL.match(text, index)
                if character is None:
                    index += 1
                    continue
                index = character.end()
                _blank(result, start, index)
                continue
            index += 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                    continue
                if index < length and text[index] == quote:
                    index += 1
                    break
                index += 1
            _blank(result, start, min(index, length))
            continue
        index += 1
    return "".join(result)


def _sql_quote_uses_backslash(text: str, quote_index: int) -> bool:
    """Return whether a PostgreSQL quote has an explicit escape prefix."""

    quote = text[quote_index]
    if quote == "'" and quote_index >= 1 and text[quote_index - 1] in {"e", "E"}:
        prefix = quote_index - 1
        if prefix == 0 or not _is_sql_identifier_continuation(
            text[prefix - 1]
        ):
            return True
    return False


def _sql_quote_escape_mode(
    text: str,
    quote_index: int,
    continuation_mode: bool | None,
    continuation_has_newline: bool,
) -> bool:
    """Return the escape mode for a quote, including SCONST continuation."""

    if (
        text[quote_index] == "'"
        and continuation_mode is not None
        and continuation_has_newline
    ):
        return continuation_mode
    return _sql_quote_uses_backslash(text, quote_index)


def mask_sql_literals_and_comments(
    text: str,
    *,
    preserve_quoted_identifiers: bool = False,
) -> str:
    """Mask SQL comments and quoted literals while retaining dollar bodies.

    Dollar-quoted function bodies contain executable PL code, so their content is
    intentionally retained. Their delimiter tokens are harmless to our rules.
    """

    result = list(text)
    length = len(text)
    index = 0
    continuation_mode: bool | None = None
    continuation_has_newline = False
    while index < length:
        if text.startswith("--", index):
            end = _find_line_break(text, index + 2)
            _blank(result, index, end)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if (
                continuation_mode is not None
                and _find_line_break(text, index) < cursor
            ):
                continuation_has_newline = True
            _blank(result, index, cursor)
            index = cursor
            continue
        if text[index] in {"'", '"'}:
            quote = text[index]
            uses_backslash = _sql_quote_escape_mode(
                text,
                index,
                continuation_mode,
                continuation_has_newline,
            )
            continuation_mode = None
            continuation_has_newline = False
            start = index
            index += 1
            while index < length:
                if text[index] == quote:
                    if index + 1 < length and text[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                if uses_backslash and text[index] == "\\":
                    index += 2
                else:
                    index += 1
            if quote == "'" or not preserve_quoted_identifiers:
                _blank(result, start, min(index, length))
            if quote == "'":
                continuation_mode = uses_backslash
            continue
        newline_end = _line_break_end(text, index)
        if newline_end is not None:
            if continuation_mode is not None:
                continuation_has_newline = True
            index = newline_end
            continue
        if text[index] not in {" ", "\t", "\f", "\v"}:
            continuation_mode = None
            continuation_has_newline = False
        index += 1
    return "".join(result)


def mask_sql_dollar_bodies(text: str) -> str:
    """Mask dollar-quoted bodies while retaining surrounding CREATE options."""

    result = list(text)
    index = 0
    length = len(text)
    state = "normal"
    block_depth = 0
    quote_uses_backslash = False
    continuation_mode: bool | None = None
    continuation_has_newline = False
    while index < length:
        if state == "normal":
            if text.startswith("--", index):
                state = "line_comment"
                index += 2
                continue
            if text.startswith("/*", index):
                state = "block_comment"
                block_depth = 1
                index += 2
                continue
            if text[index] in {"'", '"'}:
                state = "single" if text[index] == "'" else "double"
                quote_uses_backslash = _sql_quote_escape_mode(
                    text,
                    index,
                    continuation_mode,
                    continuation_has_newline,
                )
                continuation_mode = None
                continuation_has_newline = False
                index += 1
                continue
            if text[index] == "$":
                continuation_mode = None
                continuation_has_newline = False
                opening = _sql_dollar_delimiter_at(text, index)
                if opening is not None:
                    delimiter = opening.group(0)
                    closing = text.find(delimiter, opening.end())
                    end = length if closing < 0 else closing + len(delimiter)
                    _blank(result, opening.start(), end)
                    index = end
                    continue
            newline_end = _line_break_end(text, index)
            if newline_end is not None:
                if continuation_mode is not None:
                    continuation_has_newline = True
                index = newline_end
                continue
            if text[index] not in {" ", "\t", "\f", "\v"}:
                continuation_mode = None
                continuation_has_newline = False
            index += 1
            continue
        if state == "line_comment":
            newline_end = _line_break_end(text, index)
            if newline_end is not None:
                if continuation_mode is not None:
                    continuation_has_newline = True
                state = "normal"
                index = newline_end
            else:
                index += 1
            continue
        if state == "block_comment":
            if text.startswith("/*", index):
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "normal"
            else:
                newline_end = _line_break_end(text, index)
                if newline_end is not None:
                    if continuation_mode is not None:
                        continuation_has_newline = True
                    index = newline_end
                    continue
                index += 1
            continue
        quote = "'" if state == "single" else '"'
        if text[index] == quote:
            if index + 1 < length and text[index + 1] == quote:
                index += 2
            else:
                state = "normal"
                index += 1
                if quote == "'":
                    continuation_mode = quote_uses_backslash
                    continuation_has_newline = False
        elif quote_uses_backslash and text[index] == "\\":
            index = min(index + 2, length)
        else:
            index += 1
    return "".join(result)


def mask_psql_meta_commands(text: str) -> str:
    """Mask line-oriented psql commands without hiding ``\\copy`` evidence."""

    result = list(text)
    length = len(text)
    index = 0
    line_start = 0
    state = "normal"
    block_depth = 0
    dollar_delimiter = ""
    quote_uses_backslash = False
    continuation_mode: bool | None = None
    continuation_has_newline = False
    while index < length:
        if state == "normal":
            if index == line_start:
                command_start = index
                while (
                    command_start < length
                    and text[command_start] in {" ", "\t", "\f"}
                ):
                    command_start += 1
                if (
                    command_start < length
                    and text[command_start] == "\\"
                    and _PSQL_COPY_COMMAND.match(text, command_start) is None
                ):
                    end = _find_line_break(text, command_start)
                    continuation_mode = None
                    continuation_has_newline = False
                    _blank(result, line_start, end)
                    index = end
                    continue
            if text.startswith("--", index):
                state = "line_comment"
                index += 2
                continue
            if text.startswith("/*", index):
                state = "block_comment"
                block_depth = 1
                index += 2
                continue
            if text[index] == "'":
                state = "single"
                quote_uses_backslash = _sql_quote_escape_mode(
                    text,
                    index,
                    continuation_mode,
                    continuation_has_newline,
                )
                continuation_mode = None
                continuation_has_newline = False
                index += 1
                continue
            if text[index] == '"':
                state = "double"
                quote_uses_backslash = _sql_quote_uses_backslash(text, index)
                continuation_mode = None
                continuation_has_newline = False
                index += 1
                continue
            if text[index] == "$":
                continuation_mode = None
                continuation_has_newline = False
                opening = _sql_dollar_delimiter_at(text, index)
                if opening:
                    dollar_delimiter = opening.group(0)
                    state = "dollar"
                    index = opening.end()
                    continue
            newline_end = _line_break_end(text, index)
            if newline_end is not None:
                if continuation_mode is not None:
                    continuation_has_newline = True
                line_start = newline_end
                index = newline_end
                continue
            if text[index] not in {" ", "\t", "\f", "\v"}:
                continuation_mode = None
                continuation_has_newline = False
            index += 1
            continue
        if state == "line_comment":
            newline_end = _line_break_end(text, index)
            if newline_end is not None:
                if continuation_mode is not None:
                    continuation_has_newline = True
                state = "normal"
                line_start = newline_end
                index = newline_end
                continue
            index += 1
            continue
        if state == "block_comment":
            if text.startswith("/*", index):
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "normal"
            else:
                newline_end = _line_break_end(text, index)
                if newline_end is not None:
                    if continuation_mode is not None:
                        continuation_has_newline = True
                    line_start = newline_end
                    index = newline_end
                    continue
                index += 1
            continue
        if state in {"single", "double"}:
            quote = "'" if state == "single" else '"'
            if text[index] == quote:
                if index + 1 < length and text[index + 1] == quote:
                    index += 2
                else:
                    state = "normal"
                    index += 1
                    if quote == "'":
                        continuation_mode = quote_uses_backslash
                        continuation_has_newline = False
            elif quote_uses_backslash and text[index] == "\\":
                escaped_newline_end = (
                    _line_break_end(text, index + 1)
                    if index + 1 < length
                    else None
                )
                if escaped_newline_end is not None:
                    line_start = escaped_newline_end
                    index = escaped_newline_end
                else:
                    index = min(index + 2, length)
            else:
                newline_end = _line_break_end(text, index)
                if newline_end is not None:
                    line_start = newline_end
                    index = newline_end
                    continue
                index += 1
            continue
        if state == "dollar":
            if text.startswith(dollar_delimiter, index):
                index += len(dollar_delimiter)
                state = "normal"
            else:
                newline_end = _line_break_end(text, index)
                if newline_end is not None:
                    line_start = newline_end
                    index = newline_end
                    continue
                index += 1
    return "".join(result)


def mask_sql_comments(text: str) -> str:
    """Mask SQL comments but retain literals for rules such as server-side COPY."""

    result = list(text)
    length = len(text)
    index = 0
    continuation_mode: bool | None = None
    continuation_has_newline = False
    while index < length:
        if text.startswith("--", index):
            end = _find_line_break(text, index + 2)
            _blank(result, index, end)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if (
                continuation_mode is not None
                and _find_line_break(text, index) < cursor
            ):
                continuation_has_newline = True
            _blank(result, index, cursor)
            index = cursor
            continue
        if text[index] in {"'", '"'}:
            quote = text[index]
            uses_backslash = _sql_quote_escape_mode(
                text,
                index,
                continuation_mode,
                continuation_has_newline,
            )
            continuation_mode = None
            continuation_has_newline = False
            index += 1
            while index < length:
                if text[index] == quote:
                    if index + 1 < length and text[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                if uses_backslash and text[index] == "\\":
                    index += 2
                else:
                    index += 1
            if quote == "'":
                continuation_mode = uses_backslash
            continue
        newline_end = _line_break_end(text, index)
        if newline_end is not None:
            if continuation_mode is not None:
                continuation_has_newline = True
            index = newline_end
            continue
        if text[index] not in {" ", "\t", "\f", "\v"}:
            continuation_mode = None
            continuation_has_newline = False
        index += 1
    return "".join(result)


def sql_statements(text: str) -> Iterator[tuple[int, str]]:
    """Yield semicolon-delimited SQL statements without splitting dollar bodies."""

    length = len(text)
    start = 0
    index = 0
    state = "normal"
    dollar_delimiter = ""
    block_depth = 0
    quote_uses_backslash = False
    line_start = 0
    continuation_mode: bool | None = None
    continuation_has_newline = False
    while index < length:
        if state == "normal":
            if text.startswith("--", index):
                state = "line_comment"
                index += 2
                continue
            if text.startswith("/*", index):
                state = "block_comment"
                block_depth = 1
                index += 2
                continue
            if text[index] == "'":
                state = "single"
                quote_uses_backslash = _sql_quote_escape_mode(
                    text,
                    index,
                    continuation_mode,
                    continuation_has_newline,
                )
                continuation_mode = None
                continuation_has_newline = False
                index += 1
                continue
            if text[index] == '"':
                state = "double"
                quote_uses_backslash = _sql_quote_uses_backslash(text, index)
                continuation_mode = None
                continuation_has_newline = False
                index += 1
                continue
            if text[index] == "$":
                continuation_mode = None
                continuation_has_newline = False
                match = _sql_dollar_delimiter_at(text, index)
                if match:
                    dollar_delimiter = match.group(0)
                    state = "dollar"
                    index += len(dollar_delimiter)
                    continue
            if text[index] == ";":
                yield start, text[start : index + 1]
                start = index + 1
                continuation_mode = None
                continuation_has_newline = False
            newline_end = _line_break_end(text, index)
            if newline_end is not None:
                if continuation_mode is not None:
                    continuation_has_newline = True
                command_start = line_start
                while (
                    command_start < index
                    and text[command_start] in {" ", "\t", "\f"}
                ):
                    command_start += 1
                if _PSQL_COPY_COMMAND.match(text, command_start):
                    if text[start:line_start].strip():
                        yield start, text[start:line_start]
                    yield line_start, text[line_start:newline_end]
                    start = newline_end
                line_start = newline_end
                index = newline_end
                continue
            if text[index] not in {" ", "\t", "\f", "\v"}:
                continuation_mode = None
                continuation_has_newline = False
            index += 1
            continue
        if state == "line_comment":
            newline_end = _line_break_end(text, index)
            if newline_end is not None:
                if continuation_mode is not None:
                    continuation_has_newline = True
                state = "normal"
                line_start = newline_end
                index = newline_end
                continue
            index += 1
            continue
        if state == "block_comment":
            if text.startswith("/*", index):
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "normal"
            else:
                newline_end = _line_break_end(text, index)
                if newline_end is not None:
                    if continuation_mode is not None:
                        continuation_has_newline = True
                    line_start = newline_end
                    index = newline_end
                    continue
                index += 1
            continue
        if state in {"single", "double"}:
            quote = "'" if state == "single" else '"'
            if text[index] == quote:
                if index + 1 < length and text[index + 1] == quote:
                    index += 2
                else:
                    state = "normal"
                    index += 1
                    if quote == "'":
                        continuation_mode = quote_uses_backslash
                        continuation_has_newline = False
            elif quote_uses_backslash and text[index] == "\\":
                escaped_newline_end = (
                    _line_break_end(text, index + 1)
                    if index + 1 < length
                    else None
                )
                if escaped_newline_end is not None:
                    line_start = escaped_newline_end
                    index = escaped_newline_end
                else:
                    index = min(index + 2, length)
            else:
                newline_end = _line_break_end(text, index)
                if newline_end is not None:
                    line_start = newline_end
                    index = newline_end
                    continue
                index += 1
            continue
        if state == "dollar":
            if text.startswith(dollar_delimiter, index):
                index += len(dollar_delimiter)
                state = "normal"
            else:
                newline_end = _line_break_end(text, index)
                if newline_end is not None:
                    line_start = newline_end
                    index = newline_end
                    continue
                index += 1
    if text[start:].strip():
        yield start, text[start:]
