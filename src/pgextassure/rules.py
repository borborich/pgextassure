"""High-precision static rules for PostgreSQL extension source artifacts."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
import re
import tomllib
from typing import Iterable, Iterator

from .models import Finding, Severity
from .source import (
    evidence_line,
    mask_c_like,
    mask_psql_meta_commands,
    mask_sql_comments,
    mask_sql_dollar_bodies,
    mask_sql_literals_and_comments,
    one_based_line,
    sql_statements,
)


MAX_FINDINGS_PER_RULE_PER_FILE = 32


@dataclass(frozen=True, slots=True)
class ControlDocument:
    extension: str
    secondary_version: str | None
    path: str
    values: dict[str, str]
    lines: dict[str, int]
    includes: tuple[tuple[int, str], ...]


def _control_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote = value[0]
        content = value[1:-1]
        decoded: list[str] = []
        index = 0
        escapes = {
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
        }
        while index < len(content):
            if (
                content[index] == quote
                and index + 1 < len(content)
                and content[index + 1] == quote
            ):
                decoded.append(quote)
                index += 2
                continue
            if content[index] != "\\" or index + 1 >= len(content):
                decoded.append(content[index])
                index += 1
                continue
            index += 1
            if content[index] in "01234567":
                end = index + 1
                while (
                    end < len(content)
                    and end < index + 3
                    and content[end] in "01234567"
                ):
                    end += 1
                decoded.append(chr(int(content[index:end], 8)))
                index = end
                continue
            decoded.append(escapes.get(content[index], content[index]))
            index += 1
        value = "".join(decoded)
    return value.strip()


def _control_line_without_comment(line: str) -> str:
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote is None:
            if char in {"'", '"'}:
                quote = char
            elif char == "#":
                return line[:index]
        elif char == "\\" and index + 1 < len(line):
            index += 2
            continue
        elif char == quote:
            if index + 1 < len(line) and line[index + 1] == quote:
                index += 1
            else:
                quote = None
        index += 1
    return line


def parse_control(path: str, text: str) -> ControlDocument:
    values: dict[str, str] = {}
    lines: dict[str, int] = {}
    includes: list[tuple[int, str]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        candidate = _control_line_without_comment(raw_line)
        if re.match(
            r"^\s*include(?:_if_exists|_dir)?\b",
            candidate,
            re.IGNORECASE,
        ):
            includes.append((line_number, candidate.strip()))
            continue
        match = re.match(
            r"^\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*|\s+)(.*?)\s*$",
            candidate,
        )
        if not match:
            continue
        key = match.group(1).casefold()
        values[key] = _control_value(match.group(2))
        lines[key] = line_number
    filename = PurePosixPath(path).name
    if filename.endswith(".control.in"):
        extension_name = filename[: -len(".control.in")]
    elif filename.endswith(".control"):
        extension_name = filename[: -len(".control")]
    else:
        extension_name = PurePosixPath(path).stem
    extension, separator, secondary_version = extension_name.partition("--")
    return ControlDocument(
        extension=extension,
        secondary_version=secondary_version if separator else None,
        path=path,
        values=values,
        lines=lines,
        includes=tuple(includes),
    )


def _boolean(value: str | None, *, default: bool) -> bool | None:
    if value is None:
        return default
    normalized = value.strip().casefold()
    if normalized in {"t", "tr", "tru", "true", "on", "y", "ye", "yes", "1"}:
        return True
    if normalized in {
        "f",
        "fa",
        "fal",
        "fals",
        "false",
        "of",
        "off",
        "n",
        "no",
        "0",
    }:
        return False
    # Generated *.control.in files commonly contain unresolved placeholders.
    # Their eventual boolean value is unknown, so applying PostgreSQL's default
    # here would turn build-time uncertainty into a high-confidence finding.
    if "@" in normalized:
        return None
    return default


def _control_evidence(document: ControlDocument, key: str, fallback: str) -> str:
    if key not in document.values:
        return fallback
    return f"{key} = {document.values[key]}"


def scan_control(
    document: ControlDocument,
    *,
    explicit_keys: frozenset[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for line, directive in document.includes:
        findings.append(
            Finding(
                rule_id="control.external-include",
                severity=Severity.HIGH,
                title="Control metadata imports an unscanned configuration file",
                message=(
                    "PostgreSQL processes include directives recursively, so "
                    "effective extension privileges may be hidden outside this "
                    "control document."
                ),
                path=document.path,
                line=line,
                evidence=directive,
                capability="database.extension-metadata",
                remediation=(
                    "Inline the effective extension settings in the control file; "
                    "do not use include, include_if_exists, or include_dir."
                ),
            )
        )
    effective_superuser = _boolean(
        document.values.get("superuser"), default=True
    )
    trusted = _boolean(document.values.get("trusted"), default=False)
    relocatable = _boolean(document.values.get("relocatable"), default=False)

    if effective_superuser and (
        explicit_keys is None or "superuser" in explicit_keys
    ):
        explicit = "superuser" in document.values
        findings.append(
            Finding(
                rule_id="control.superuser-required",
                severity=Severity.HIGH,
                title="Extension installation requires superuser authority",
                message=(
                    "The control file enables superuser installation."
                    if explicit
                    else "The control file omits superuser=false; PostgreSQL defaults "
                    "this setting to true."
                ),
                path=document.path,
                line=document.lines.get("superuser", 1),
                evidence=_control_evidence(
                    document, "superuser", "superuser omitted (default: true)"
                ),
                capability="database.superuser-install",
                remediation=(
                    "Set superuser = false when every installation action is safe "
                    "for the extension owner; otherwise document and tightly gate "
                    "the privileged installation."
                ),
            )
        )

    if trusted and (
        explicit_keys is None or "trusted" in explicit_keys
    ):
        findings.append(
            Finding(
                rule_id="control.trusted-install",
                severity=Severity.HIGH,
                title="Extension is installable through PostgreSQL's trusted path",
                message=(
                    "trusted=true permits users with CREATE privilege to request "
                    "installation; privileged scripts therefore require exceptional "
                    "care."
                ),
                path=document.path,
                line=document.lines.get("trusted", 1),
                evidence=_control_evidence(document, "trusted", "trusted = true"),
                capability="database.trusted-install",
                remediation=(
                    "Use trusted = false unless the complete install and update "
                    "surface has been designed and reviewed for unprivileged use."
                ),
            )
        )

    if relocatable and (
        explicit_keys is None or "relocatable" in explicit_keys
    ):
        findings.append(
            Finding(
                rule_id="control.relocatable",
                severity=Severity.LOW,
                title="Extension permits schema relocation",
                message=(
                    "relocatable=true makes object resolution and search_path "
                    "discipline part of the extension's security boundary."
                ),
                path=document.path,
                line=document.lines.get("relocatable", 1),
                evidence=_control_evidence(
                    document, "relocatable", "relocatable = true"
                ),
                capability="database.schema-relocation",
                remediation=(
                    "Prefer relocatable = false for extensions with fixed-schema or "
                    "security-definer objects; otherwise schema-qualify references."
                ),
            )
        )

    risky_requirements = {
        "dblink",
        "file_fdw",
        "postgres_fdw",
        "http",
        "pgsql-http",
        "plpythonu",
        "plpython2u",
        "plpython3u",
        "plperlu",
        "plsh",
    }
    requirements = set(
        _control_identifier_list(document.values.get("requires", ""))
    )
    risky = sorted(requirements & risky_requirements)
    if risky and (
        explicit_keys is None or "requires" in explicit_keys
    ):
        findings.append(
            Finding(
                rule_id="control.risky-requirement",
                severity=Severity.MEDIUM,
                title="Extension declares a security-sensitive requirement",
                message=(
                    "The extension depends on components that can expose external "
                    "I/O or untrusted procedural-language capabilities: "
                    + ", ".join(risky)
                    + "."
                ),
                path=document.path,
                line=document.lines.get("requires", 1),
                evidence=_control_evidence(document, "requires", ", ".join(risky)),
                capability="database.extension-dependency",
                remediation=(
                    "Remove unnecessary requirements and review the privileges and "
                    "external I/O surface of every retained dependency."
                ),
            )
        )
    return findings


def _control_identifier_list(value: str) -> tuple[str, ...]:
    """Parse PostgreSQL's comma-separated identifier-list form conservatively."""

    items: list[str] = []
    start = 0
    index = 0
    quoted = False
    while index <= len(value):
        if index == len(value) or (value[index] == "," and not quoted):
            item = value[start:index].strip()
            if item:
                if (
                    len(item) >= 2
                    and item[0] == '"'
                    and item[-1] == '"'
                ):
                    item = item[1:-1].replace('""', '"')
                items.append(item.casefold())
            start = index + 1
            index += 1
            continue
        if value[index] == '"':
            if quoted and index + 1 < len(value) and value[index + 1] == '"':
                index += 2
                continue
            quoted = not quoted
        index += 1
    return tuple(items)


def _finding_at(
    *,
    rule_id: str,
    severity: Severity,
    title: str,
    message: str,
    path: str,
    text: str,
    offset: int,
    capability: str,
    remediation: str,
    evidence: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        path=path,
        line=one_based_line(text, offset),
        evidence=evidence if evidence is not None else evidence_line(text, offset),
        capability=capability,
        remediation=remediation,
    )


class _FindingLimiter:
    """Bound report growth while preserving a gate-triggering sample."""

    def __init__(self, limit: int = MAX_FINDINGS_PER_RULE_PER_FILE) -> None:
        self.limit = limit
        self.counts: dict[str, int] = defaultdict(int)

    def allow(self, rule_id: str) -> bool:
        self.counts[rule_id] += 1
        return self.counts[rule_id] <= self.limit

    def annotate(self, findings: list[Finding]) -> list[Finding]:
        for rule_id, count in sorted(self.counts.items()):
            if count <= self.limit:
                continue
            for index, finding in enumerate(findings):
                if finding.rule_id != rule_id:
                    continue
                findings[index] = replace(
                    finding,
                    evidence=(
                        f"{finding.evidence} [showing first {self.limit} "
                        f"of {count} matches in this file]"
                    ),
                )
                break
        return findings


_SQL_UNQUOTED_IDENTIFIER = r"(?:[A-Za-z_]|[^\x00-\x7f])(?:[A-Za-z0-9_$]|[^\x00-\x7f])*"
_SQL_UNICODE_QUOTED_IDENTIFIER = (
    r'(?:[Uu]&\"(?:\"\"|[^\"])+\"'
    r"(?:\s*(?i:UESCAPE)\s*'(?:''|[^'])*')?)"
)
_SQL_QUOTED_IDENTIFIER = (
    rf'(?:{_SQL_UNICODE_QUOTED_IDENTIFIER}|\"(?:\"\"|[^\"])+\")'
)
_EXTSCHEMA_PLACEHOLDER = r"@extschema(?::[^@\s]+)?@"
_SQL_IDENTIFIER = (
    rf"(?:{_EXTSCHEMA_PLACEHOLDER}|{_SQL_QUOTED_IDENTIFIER}|"
    rf"{_SQL_UNQUOTED_IDENTIFIER})"
)
_EXTSCHEMA_PLACEHOLDER_TOKEN = re.compile(_EXTSCHEMA_PLACEHOLDER)
_SQL_QUALIFIED_IDENTIFIER = (
    rf"{_SQL_IDENTIFIER}(?:\s*\.\s*{_SQL_IDENTIFIER})*"
)
_SQL_IDENTIFIER_TOKEN = re.compile(_SQL_IDENTIFIER)
_SQL_DOLLAR_STRING = re.compile(
    r"\$(?:[A-Za-z_]|[^\x00-\x7f])"
    r"(?:[A-Za-z0-9_]|[^\x00-\x7f])*\$|\$\$"
)
_CREATE_ROUTINE = re.compile(
    rf"\bCREATE\s+(?:OR\s+REPLACE\s+)?"
    rf"(?P<kind>FUNCTION|PROCEDURE)\s+"
    rf"(?P<name>{_SQL_QUALIFIED_IDENTIFIER})\s*(?P<open>\()",
    re.IGNORECASE,
)
_ALTER_ROUTINE = re.compile(
    rf"\bALTER\s+(?P<kind>FUNCTION|PROCEDURE|ROUTINE)\s+"
    rf"(?P<name>{_SQL_QUALIFIED_IDENTIFIER})(?:\s*(?P<open>\())?",
    re.IGNORECASE,
)
_REVOKE_ROUTINE_START = re.compile(
    r"^\s*REVOKE\s+(?:EXECUTE|ALL(?:\s+PRIVILEGES)?)\s+ON\s+"
    r"(?P<kind>FUNCTION|PROCEDURE|ROUTINE)\b",
    re.IGNORECASE,
)
_ROUTINE_REFERENCE = re.compile(
    rf"(?P<name>{_SQL_QUALIFIED_IDENTIFIER})\s*\(",
    re.IGNORECASE,
)
_FROM_PUBLIC = re.compile(
    r"\bFROM\s+(?:GROUP\s+)?PUBLIC\b",
    re.IGNORECASE,
)
_GRANT_ROUTINE_START = re.compile(
    r"^\s*GRANT\s+(?:EXECUTE|ALL(?:\s+PRIVILEGES)?)\s+ON\s+"
    r"(?:(?:FUNCTION|PROCEDURE|ROUTINE)\b|"
    r"ALL\s+(?:FUNCTIONS|PROCEDURES|ROUTINES)\s+IN\s+SCHEMA\b)",
    re.IGNORECASE,
)
_RETURNS_EVENT_TRIGGER = re.compile(
    r"\bRETURNS\s+(?:(?:pg_catalog)\s*\.\s*)?event_trigger\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _SqlToken:
    kind: str
    raw: str
    start: int
    end: int


def _quoted_token_end(
    text: str,
    quote_index: int,
    *,
    backslash_escapes: bool,
) -> int:
    quote = text[quote_index]
    index = quote_index + 1
    while index < len(text):
        if text[index] == quote:
            if index + 1 < len(text) and text[index + 1] == quote:
                index += 2
                continue
            return index + 1
        if backslash_escapes and text[index] == "\\":
            index += 2
        else:
            index += 1
    return len(text)


def _sql_tokens(text: str) -> Iterator[_SqlToken]:
    """Yield a bounded lexical token stream without interpreting SQL bodies."""

    index = 0
    length = len(text)
    while index < length:
        if text[index].isspace():
            index += 1
            continue
        if text.startswith("--", index):
            newline = re.search(r"[\r\n]", text[index + 2 :])
            index = (
                length
                if newline is None
                else index + 2 + newline.start() + 1
            )
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
            index = cursor
            continue

        start = index
        if text[index] == "@":
            placeholder = _EXTSCHEMA_PLACEHOLDER_TOKEN.match(text, index)
            if placeholder is not None:
                end = placeholder.end()
                yield _SqlToken(
                    "placeholder",
                    text[start:end],
                    start,
                    end,
                )
                index = end
                continue
        if text[index] == "$":
            delimiter = _SQL_DOLLAR_STRING.match(text, index)
            if delimiter is not None:
                marker = delimiter.group(0)
                closing = text.find(marker, delimiter.end())
                end = length if closing < 0 else closing + len(marker)
                yield _SqlToken("string", text[start:end], start, end)
                index = end
                continue

        quote_index: int | None = None
        kind = ""
        backslash_escapes = False
        if text[index] in {"e", "E"} and index + 1 < length:
            if text[index + 1] == "'":
                quote_index = index + 1
                kind = "string"
                backslash_escapes = True
        if (
            quote_index is None
            and text[index] in {"u", "U"}
            and index + 2 < length
            and text[index + 1] == "&"
            and text[index + 2] in {"'", '"'}
        ):
            quote_index = index + 2
            kind = "string" if text[quote_index] == "'" else "identifier"
        if quote_index is None and text[index] in {"'", '"'}:
            quote_index = index
            kind = "string" if text[index] == "'" else "identifier"
        if quote_index is not None:
            end = _quoted_token_end(
                text,
                quote_index,
                backslash_escapes=backslash_escapes,
            )
            yield _SqlToken(kind, text[start:end], start, end)
            index = end
            continue

        character = text[index]
        if (
            character.isalpha()
            or character == "_"
            or ord(character) >= 128
        ):
            index += 1
            while index < length:
                character = text[index]
                if (
                    character.isalnum()
                    or character in {"_", "$"}
                    or ord(character) >= 128
                ):
                    index += 1
                else:
                    break
            yield _SqlToken("word", text[start:index], start, index)
            continue
        if character.isdigit():
            index += 1
            while index < length and (
                text[index].isalnum() or text[index] in {"_", ".", "$"}
            ):
                index += 1
            yield _SqlToken("number", text[start:index], start, index)
            continue
        index += 1
        yield _SqlToken("symbol", text[start:index], start, index)


def _unicode_identifier_escape_spans(
    text: str,
) -> Iterator[tuple[int, int]]:
    """Yield UESCAPE suffixes following U& quoted identifiers."""

    tokens = list(_sql_tokens(text))
    index = 0
    while index < len(tokens):
        identifier = tokens[index]
        if (
            identifier.kind != "identifier"
            or not identifier.raw[:2].casefold() == "u&"
            or index + 2 >= len(tokens)
        ):
            index += 1
            continue
        keyword = tokens[index + 1]
        if (
            keyword.kind != "word"
            or _postgres_identifier_fold(keyword.raw) != "uescape"
            or text[identifier.end : keyword.start].strip()
        ):
            index += 1
            continue
        value = tokens[index + 2]
        if value.kind != "string":
            index += 1
            continue
        last = index + 2
        while last + 1 < len(tokens):
            following = tokens[last + 1]
            gap = text[tokens[last].end : following.start]
            if (
                following.kind != "string"
                or not any(newline in gap for newline in ("\r", "\n"))
            ):
                break
            last += 1
        yield identifier.end, tokens[last].end
        index = last + 1


def _unicode_identifier_view(text: str, base: str) -> str:
    """Expose all valid UESCAPE literal forms to the bounded identifier regex."""

    result = list(base)
    marker = "UESCAPE'!'"
    for start, end in _unicode_identifier_escape_spans(text):
        width = end - start
        if width < len(marker):
            continue
        replacement = (" " * (width - len(marker))) + marker
        result[start:end] = replacement
    return "".join(result)


def _token_value(token: _SqlToken) -> str | None:
    """Return a comparison value; ``None`` means a Unicode escape is unresolved."""

    raw = token.raw
    if token.kind == "word":
        return raw.casefold()
    if raw.startswith("$"):
        delimiter = _SQL_DOLLAR_STRING.match(raw)
        if delimiter is None or not raw.endswith(delimiter.group(0)):
            return None
        marker = delimiter.group(0)
        return raw[len(marker) : -len(marker)].casefold()

    quote_index = 0
    unicode_escape = False
    backslash_escape = False
    if len(raw) >= 3 and raw[:2].casefold() == "u&":
        quote_index = 2
        unicode_escape = True
    elif len(raw) >= 2 and raw[0] in {"e", "E"} and raw[1] == "'":
        quote_index = 1
        backslash_escape = True
    if quote_index >= len(raw) or raw[quote_index] not in {"'", '"'}:
        return None
    quote = raw[quote_index]
    if not raw.endswith(quote):
        return None
    value = raw[quote_index + 1 : -1].replace(quote * 2, quote)
    if unicode_escape and "\\" in value:
        return None
    if backslash_escape and "\\" in value:
        return None
    return value.casefold()


_ASCII_UPPER_TO_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
)


def _postgres_identifier_fold(value: str) -> str:
    """Apply PostgreSQL's ASCII-only folding for unquoted identifiers."""

    return value.translate(_ASCII_UPPER_TO_LOWER)


def _decode_unicode_identifier(
    content: str,
    escape: str,
) -> str | None:
    """Decode PostgreSQL U& identifier escapes, returning None if uncertain."""

    decoded: list[str] = []
    index = 0
    while index < len(content):
        if content[index] != escape:
            decoded.append(content[index])
            index += 1
            continue
        if index + 1 < len(content) and content[index + 1] == escape:
            decoded.append(escape)
            index += 2
            continue
        hexadecimal_start = index + 1
        digits = 4
        if (
            hexadecimal_start < len(content)
            and content[hexadecimal_start] == "+"
        ):
            hexadecimal_start += 1
            digits = 6
        hexadecimal_end = hexadecimal_start + digits
        encoded = content[hexadecimal_start:hexadecimal_end]
        if (
            len(encoded) != digits
            or re.fullmatch(r"[0-9A-Fa-f]+", encoded) is None
        ):
            return None
        codepoint = int(encoded, 16)
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            return None
        decoded.append(chr(codepoint))
        index = hexadecimal_end
    return "".join(decoded)


def _quoted_identifier_canonical_value(content: str) -> str:
    if (
        content == _postgres_identifier_fold(content)
        and re.fullmatch(_SQL_UNQUOTED_IDENTIFIER, content)
    ):
        return "identifier:" + content
    return "quoted:" + content


def _canonical_quoted_identifier(raw: str) -> str:
    quote_index = 2 if raw[:2].casefold() == "u&" else 0
    if (
        quote_index >= len(raw)
        or raw[quote_index] != '"'
    ):
        return "quoted:" + raw
    first = next(_sql_tokens(raw), None)
    if (
        first is None
        or first.kind != "identifier"
        or not first.raw.endswith('"')
    ):
        return "quoted:" + raw
    content = first.raw[quote_index + 1 : -1].replace('""', '"')
    if not quote_index:
        return _quoted_identifier_canonical_value(content)

    escape = "\\"
    suffix_tokens = list(_sql_tokens(raw[first.end :]))
    if suffix_tokens:
        if (
            suffix_tokens[0].kind != "word"
            or _postgres_identifier_fold(suffix_tokens[0].raw) != "uescape"
        ):
            return "unicode-uncertain:" + re.sub(r"\s+", " ", raw.strip())
        string_tokens = [
            token for token in suffix_tokens[1:] if token.kind == "string"
        ]
        if len(string_tokens) != len(suffix_tokens) - 1:
            return "unicode-uncertain:" + re.sub(r"\s+", " ", raw.strip())
        values = [_token_value(token) for token in string_tokens]
        if any(value is None for value in values):
            return "unicode-uncertain:" + re.sub(r"\s+", " ", raw.strip())
        escape = "".join(value or "" for value in values)
        if len(escape) != 1:
            return "unicode-uncertain:" + re.sub(r"\s+", " ", raw.strip())

    decoded = _decode_unicode_identifier(content, escape)
    if decoded is None:
        return "unicode-uncertain:" + re.sub(r"\s+", " ", raw.strip())
    return _quoted_identifier_canonical_value(decoded)


def _normalized_identifier(raw: str) -> str:
    parts = []
    view = _unicode_identifier_view(raw, raw)
    for match in _SQL_IDENTIFIER_TOKEN.finditer(view):
        value = raw[match.start() : match.end()]
        if value.casefold().startswith('u&"') or value.startswith('"'):
            value = _canonical_quoted_identifier(value)
        else:
            value = "identifier:" + _postgres_identifier_fold(value)
        parts.append(value)
    return ".".join(parts)


def _parenthesized_content(text: str, opening: int) -> str:
    depth = 0
    index = opening
    quoted_identifier = False
    while index < len(text):
        character = text[index]
        if quoted_identifier:
            if character == '"':
                if index + 1 < len(text) and text[index + 1] == '"':
                    index += 2
                    continue
                quoted_identifier = False
            index += 1
            continue
        if character == '"':
            quoted_identifier = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return text[opening + 1 : index]
        index += 1
    return text[opening + 1 :]


def _canonical_argument_tokens(arguments: str) -> tuple[str, ...]:
    tokens: list[str] = []
    for token in _sql_tokens(arguments):
        if token.kind == "word":
            tokens.append(
                "identifier:" + _postgres_identifier_fold(token.raw)
            )
        elif token.kind == "identifier":
            tokens.append(_canonical_quoted_identifier(token.raw))
        else:
            tokens.append(f"{token.kind[0]}:{token.raw}")
    return tuple(tokens)


_MULTIWORD_TYPE_STARTS = {
    "bit",
    "character",
    "double",
    "interval",
    "national",
    "time",
    "timestamp",
}
_ARGUMENT_MODES = {"in", "inout", "out", "variadic"}


def _canonical_create_argument_tokens(arguments: str) -> tuple[str, ...]:
    """Normalize CREATE arguments to PostgreSQL identity-argument syntax."""

    raw_arguments: list[list[_SqlToken]] = [[]]
    depth = 0
    for token in _sql_tokens(arguments):
        if token.kind == "symbol":
            if token.raw in {"(", "["}:
                depth += 1
            elif token.raw in {")", "]"} and depth:
                depth -= 1
            elif token.raw == "," and depth == 0:
                raw_arguments.append([])
                continue
        raw_arguments[-1].append(token)

    identity: list[str] = []
    for argument in raw_arguments:
        if not argument:
            continue
        trimmed: list[_SqlToken] = []
        nested = 0
        for token in argument:
            if token.kind == "symbol":
                if token.raw in {"(", "["}:
                    nested += 1
                elif token.raw in {")", "]"} and nested:
                    nested -= 1
                elif token.raw == "=" and nested == 0:
                    break
            if (
                nested == 0
                and token.kind == "word"
                and _postgres_identifier_fold(token.raw) == "default"
            ):
                break
            trimmed.append(token)
        if not trimmed:
            continue

        first_word = (
            _postgres_identifier_fold(trimmed[0].raw)
            if trimmed[0].kind == "word"
            else None
        )
        if first_word in _ARGUMENT_MODES:
            if first_word == "out":
                continue
            trimmed = trimmed[1:]
            if not trimmed:
                continue
            first_word = (
                _postgres_identifier_fold(trimmed[0].raw)
                if trimmed[0].kind == "word"
                else None
            )

        if (
            len(trimmed) >= 2
            and trimmed[0].kind in {"word", "identifier"}
            and not (
                trimmed[1].kind == "symbol"
                and trimmed[1].raw in {".", "[", "%"}
            )
            and first_word not in _MULTIWORD_TYPE_STARTS
        ):
            trimmed = trimmed[1:]

        if identity:
            identity.append("s:,")
        for token in trimmed:
            if token.kind == "word":
                identity.append(
                    "identifier:" + _postgres_identifier_fold(token.raw)
                )
            elif token.kind == "identifier":
                identity.append(_canonical_quoted_identifier(token.raw))
            else:
                identity.append(f"{token.kind[0]}:{token.raw}")
    return tuple(identity)


_RoutineKey = tuple[str, str, tuple[str, ...]]


def _routine_key(
    kind: str,
    name: str,
    statement: str,
    opening: int | None,
    *,
    declaration: bool = False,
) -> _RoutineKey:
    arguments = (
        _parenthesized_content(statement, opening)
        if opening is not None
        else None
    )
    return (
        kind.casefold(),
        _normalized_identifier(name),
        (
            (
                _canonical_create_argument_tokens(arguments)
                if declaration
                else _canonical_argument_tokens(arguments)
            )
            if arguments is not None
            else ("wildcard:any-signature",)
        ),
    )


def _routine_identity_evidence(
    kind: str,
    name: str,
    statement: str,
    opening: int | None,
) -> str:
    arguments = (
        " ".join(_parenthesized_content(statement, opening).split())
        if opening is not None
        else None
    )
    return (
        f"routine = {kind.casefold()} {name}"
        + (f"({arguments})" if arguments is not None else "")
    )


def _configuration_identifier(
    token: _SqlToken,
) -> tuple[str | None, bool]:
    """Return a configuration name and whether its Unicode syntax is uncertain."""

    if token.kind == "word":
        return _postgres_identifier_fold(token.raw), False
    if token.kind != "identifier":
        return None, False
    raw = token.raw
    unicode_form = raw[:2].casefold() == "u&"
    quote_index = 2 if unicode_form else 0
    if (
        quote_index >= len(raw)
        or raw[quote_index] != '"'
        or not raw.endswith('"')
    ):
        return None, unicode_form
    content = raw[quote_index + 1 : -1].replace('""', '"')
    if unicode_form and "\\" in content:
        return None, True
    # PostgreSQL configuration parameter names are case-insensitive even when
    # the SQL grammar supplies them as quoted identifiers.
    return _postgres_identifier_fold(content), False


def _search_path_entry(token: _SqlToken) -> str | None:
    if token.kind == "placeholder":
        return token.raw
    if token.kind == "word":
        return _postgres_identifier_fold(token.raw)
    if token.kind != "identifier" or token.raw[:2].casefold() == "u&":
        return None
    if not token.raw.startswith('"') or not token.raw.endswith('"'):
        return None
    return token.raw[1:-1].replace('""', '"')


def _before_atomic_body(statement: str) -> str:
    configuration = mask_sql_dollar_bodies(statement)
    configuration_tokens = list(_sql_tokens(configuration))
    for index, token in enumerate(configuration_tokens[:-1]):
        following = configuration_tokens[index + 1]
        if (
            token.kind == "word"
            and following.kind == "word"
            and _postgres_identifier_fold(token.raw) == "begin"
            and _postgres_identifier_fold(following.raw) == "atomic"
        ):
            return configuration[: token.start]
    return configuration


def _routine_body(statement: str) -> str | None:
    """Return a plainly quoted routine body, or ``None`` when uncertain."""

    tokens = list(_sql_tokens(statement))
    for index, token in enumerate(tokens[:-1]):
        if (
            token.kind != "word"
            or _postgres_identifier_fold(token.raw) != "as"
        ):
            continue
        body = tokens[index + 1]
        if body.kind != "string":
            return None
        raw = body.raw
        if raw.startswith("$"):
            delimiter = _SQL_DOLLAR_STRING.match(raw)
            if delimiter is None:
                return None
            marker = delimiter.group(0)
            if not raw.endswith(marker) or len(raw) < len(marker) * 2:
                return None
            return raw[len(marker) : -len(marker)]
        quote_index = 1 if raw[:1].casefold() == "e" else 0
        if (
            quote_index >= len(raw)
            or raw[quote_index] != "'"
            or not raw.endswith("'")
        ):
            return None
        content = raw[quote_index + 1 : -1].replace("''", "'")
        if quote_index and "\\" in content:
            return None
        return content
    return None


def _routine_body_mentions_search_path(statement: str) -> bool:
    body = _routine_body(statement)
    if body is None:
        return False
    lexical = mask_sql_comments(body)
    return (
        re.search(
            r"\b(?:search_path|set_config)\b",
            lexical,
            re.IGNORECASE,
        )
        is not None
    )


def _routine_body_has_unqualified_resolution(statement: str) -> bool:
    """Recognize a plainly unqualified callable or relation lookup.

    Returning ``False`` never establishes that the complete routine is safe;
    unknown, call-free, and fully qualified bodies remain visible as manual
    review findings.
    """

    body = _routine_body(statement)
    if body is None:
        return False
    lexical = mask_sql_literals_and_comments(
        body,
        preserve_quoted_identifiers=True,
    )
    tokens = list(_sql_tokens(lexical))
    structural = {
        "case",
        "else",
        "elsif",
        "if",
        "loop",
        "return",
        "then",
        "when",
        "while",
    }
    relation_keywords = {"from", "join", "update"}
    for index, token in enumerate(tokens[:-1]):
        if (
            token.kind == "word"
            and _postgres_identifier_fold(token.raw) in relation_keywords
        ):
            candidate_index = index + 1
            candidate = tokens[candidate_index]
            if (
                candidate.kind == "word"
                and _postgres_identifier_fold(candidate.raw) == "only"
                and candidate_index + 1 < len(tokens)
            ):
                candidate_index += 1
                candidate = tokens[candidate_index]
            if candidate.kind in {"word", "identifier", "placeholder"}:
                after_index = candidate_index + 1
                qualified = (
                    after_index < len(tokens)
                    and tokens[after_index].kind == "symbol"
                    and tokens[after_index].raw == "."
                )
                if not qualified:
                    return True
        if token.kind not in {"word", "identifier"}:
            continue
        following = tokens[index + 1]
        if following.kind != "symbol" or following.raw != "(":
            continue
        if (
            index
            and tokens[index - 1].kind == "symbol"
            and tokens[index - 1].raw == "."
        ):
            continue
        if (
            token.kind == "word"
            and _postgres_identifier_fold(token.raw) in structural
        ):
            continue
        return True
    return False


def _search_path_mutations(statement: str) -> Iterator[tuple[int, bool]]:
    configuration = _before_atomic_body(statement)

    tokens = iter(_sql_tokens(configuration))
    pending: _SqlToken | None = None
    while True:
        token = pending if pending is not None else next(tokens, None)
        pending = None
        if token is None:
            return
        if token.kind != "word":
            continue
        keyword = _postgres_identifier_fold(token.raw)
        if keyword == "reset":
            name_token = next(tokens, None)
            if name_token is None:
                continue
            name, uncertain = _configuration_identifier(name_token)
            if name_token.raw[:2].casefold() == "u&":
                following = next(tokens, None)
                if (
                    following is not None
                    and following.kind == "word"
                    and _postgres_identifier_fold(following.raw) == "uescape"
                ):
                    next(tokens, None)
                    uncertain = True
                else:
                    pending = following
            if name == "all" or name == "search_path" or uncertain:
                yield token.start, False
            continue
        if keyword != "set":
            continue

        name_token = next(tokens, None)
        if name_token is None:
            continue
        name, uncertain = _configuration_identifier(name_token)
        operator = next(tokens, None)
        if operator is None:
            continue
        if (
            name_token.raw[:2].casefold() == "u&"
            and operator.kind == "word"
            and _postgres_identifier_fold(operator.raw) == "uescape"
        ):
            next(tokens, None)
            operator = next(tokens, None)
            uncertain = True
            if operator is None:
                continue

        is_search_path = name == "search_path" or uncertain
        if not is_search_path:
            pending = operator
            continue
        if (
            operator.kind == "word"
            and _postgres_identifier_fold(operator.raw) == "from"
        ):
            current = next(tokens, None)
            if (
                current is not None
                and current.kind == "word"
                and _postgres_identifier_fold(current.raw) == "current"
            ):
                yield token.start, False
            continue
        if not (
            (operator.kind == "symbol" and operator.raw == "=")
            or (
                operator.kind == "word"
                and _postgres_identifier_fold(operator.raw) == "to"
            )
        ):
            pending = operator
            continue
        if uncertain:
            yield token.start, False
            continue

        entries: list[str] = []
        valid = True
        expect_entry = True
        while True:
            value_token = next(tokens, None)
            if value_token is None:
                break
            if expect_entry:
                value = _search_path_entry(value_token)
                if value is None:
                    valid = False
                    pending = value_token
                    break
                entries.append(value)
                expect_entry = False
                continue
            if value_token.kind == "symbol" and value_token.raw == ",":
                expect_entry = True
                continue
            pending = value_token
            break
        safe = (
            valid
            and len(entries) >= 2
            and not expect_entry
            and entries[-1] == "pg_temp"
            and "pg_temp" not in entries[:-1]
            and not any(item in {"public", "$user"} for item in entries)
        )
        yield token.start, safe


def _safe_search_path(statement: str) -> bool:
    safe = False
    for _offset, safe in _search_path_mutations(statement):
        pass
    return safe


def _routine_state_matches(candidate: _RoutineKey, known: _RoutineKey) -> bool:
    return (
        candidate[1:] == known[1:]
        and (
            candidate[0] == known[0]
            or candidate[0] == "routine"
            or known[0] == "routine"
        )
    )


def _routine_name_matches(candidate: _RoutineKey, known: _RoutineKey) -> bool:
    return (
        candidate[1] == known[1]
        and (
            candidate[0] == known[0]
            or candidate[0] == "routine"
            or known[0] == "routine"
        )
    )


def _search_path_mutation(statement: str) -> tuple[bool, int]:
    last: tuple[int, bool] | None = None
    for mutation in _search_path_mutations(statement):
        last = mutation
    if last is None:
        return False, 0
    offset, safe = last
    return not safe, offset


def _copy_capability(statement: str) -> tuple[str, int] | None:
    tokens = iter(_sql_tokens(statement))
    first = next(tokens, None)
    if first is None:
        return None
    if first.kind == "symbol" and first.raw == "\\":
        first = next(tokens, None)
    if (
        first is None
        or first.kind != "word"
        or first.raw.casefold() != "copy"
    ):
        return None

    depth = 0
    for token in tokens:
        if token.kind == "symbol":
            if token.raw == "(":
                depth += 1
            elif token.raw == ")" and depth:
                depth -= 1
            continue
        if (
            depth == 0
            and token.kind == "word"
            and token.raw.casefold() in {"from", "to"}
        ):
            target = next(tokens, None)
            if target is None:
                return None
            if (
                target.kind == "word"
                and target.raw.casefold() == "program"
            ):
                return "program", target.start
            if target.kind == "string":
                return "file", target.start
            return None
    return None


_UNTRUSTED_LANGUAGES = frozenset(
    {
        "plpythonu",
        "plpython2u",
        "plpython3u",
        "plperlu",
        "plsh",
        "pljava",
        "pltclu",
    }
)


def _untrusted_language_uses(text: str) -> Iterator[tuple[int, str]]:
    tokens = iter(_sql_tokens(text))
    pending: _SqlToken | None = None
    while True:
        token = pending if pending is not None else next(tokens, None)
        pending = None
        if token is None:
            return
        if (
            token.kind != "word"
            or _postgres_identifier_fold(token.raw) != "language"
        ):
            continue

        value_token = next(tokens, None)
        if (
            value_token is None
            or value_token.kind not in {"word", "identifier", "string"}
        ):
            continue
        parts = [value_token]
        following = next(tokens, None)
        while (
            parts[-1].kind == "string"
            and following is not None
            and following.kind == "string"
            and any(
                newline in text[parts[-1].end : following.start]
                for newline in ("\r", "\n")
            )
        ):
            parts.append(following)
            following = next(tokens, None)

        values = [_token_value(part) for part in parts]
        uncertain = any(value is None for value in values)
        inherited_escape_state = parts[0].raw[:1].casefold() == "e" or (
            parts[0].raw[:2].casefold() == "u&"
        )
        if inherited_escape_state and any("\\" in part.raw for part in parts):
            # PostgreSQL keeps the first literal's E/U& lexer state across
            # newline-concatenated segments. Fail closed instead of treating a
            # later plain-looking quote as an ordinary literal.
            uncertain = True
        unicode_syntax = any(
            part.raw[:2].casefold() == "u&" for part in parts
        )
        if (
            unicode_syntax
            and following is not None
            and following.kind == "word"
            and _postgres_identifier_fold(following.raw) == "uescape"
        ):
            uncertain = True
            next(tokens, None)
            following = next(tokens, None)
        pending = following

        language_name = (
            "".join(value for value in values if value is not None)
            if not uncertain
            else ""
        )
        if language_name in _UNTRUSTED_LANGUAGES:
            yield token.start, language_name
        elif uncertain:
            yield token.start, "escaped language name"


def scan_sql(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    limiter = _FindingLimiter()
    lexical_text = mask_psql_meta_commands(text)
    masked = mask_sql_literals_and_comments(lexical_text)
    identifier_masked = mask_sql_literals_and_comments(
        lexical_text,
        preserve_quoted_identifiers=True,
    )

    def public_after(statement: str, keyword: str) -> bool:
        marker = re.search(rf"\b{keyword}\b", statement, re.IGNORECASE)
        if marker is None:
            return False
        region = statement[marker.end() :]
        terminator = re.search(
            r"\b(?:WITH\s+GRANT\s+OPTION|GRANTED\s+BY|CASCADE|RESTRICT)\b|;",
            region,
            re.IGNORECASE,
        )
        if terminator:
            region = region[: terminator.start()]
        return re.search(r"\bPUBLIC\b", region, re.IGNORECASE) is not None

    revoked_at: dict[_RoutineKey, int] = {}
    definer_routines: list[tuple[int, int, _RoutineKey, str, bool]] = []
    known_definers: set[_RoutineKey] = set()
    comments_masked = mask_sql_comments(lexical_text)
    for statement_offset, comments_statement in sql_statements(comments_masked):
        statement_end = statement_offset + len(comments_statement)
        statement = masked[statement_offset:statement_end]
        identifier_statement = identifier_masked[statement_offset:statement_end]
        routine_identifier_view = _unicode_identifier_view(
            comments_statement,
            identifier_statement,
        )
        routine_keyword_view = mask_sql_dollar_bodies(
            routine_identifier_view
        )

        revoke = _REVOKE_ROUTINE_START.match(statement)
        if revoke is not None and public_after(statement, "FROM"):
            from_marker = re.search(r"\bFROM\b", statement, re.IGNORECASE)
            before_from = (
                routine_keyword_view
                if from_marker is None
                else routine_keyword_view[: from_marker.start()]
            )
            for reference in _ROUTINE_REFERENCE.finditer(
                before_from,
                revoke.end(),
            ):
                raw_name = comments_statement[
                    reference.start("name") : reference.end("name")
                ]
                key = _routine_key(
                    revoke.group("kind"),
                    raw_name,
                    routine_keyword_view,
                    reference.end() - 1,
                )
                if key[1]:
                    revoked_at[key] = max(
                        revoked_at.get(key, -1),
                        statement_offset,
                    )

        def routine_match(
            pattern: re.Pattern[str],
        ) -> re.Match[str] | None:
            return pattern.search(routine_keyword_view)

        create = routine_match(_CREATE_ROUTINE)
        alter = routine_match(_ALTER_ROUTINE)
        configuration_view = _before_atomic_body(statement)
        definer = re.search(
            r"\bSECURITY\s+DEFINER\b",
            configuration_view,
            re.IGNORECASE,
        )
        invoker = re.search(
            r"\bSECURITY\s+INVOKER\b",
            configuration_view,
            re.IGNORECASE,
        )
        routine = create or alter
        raw_routine_name = (
            comments_statement[
                routine.start("name") : routine.end("name")
            ]
            if routine is not None
            else ""
        )
        routine_key = (
            _routine_key(
                routine.group("kind"),
                raw_routine_name,
                routine_keyword_view,
                (
                    routine.start("open")
                    if routine.group("open") is not None
                    else None
                ),
                declaration=create is not None,
            )
            if routine is not None
            else None
        )
        routine_evidence = (
            _routine_identity_evidence(
                routine.group("kind"),
                raw_routine_name,
                routine_identifier_view,
                (
                    routine.start("open")
                    if routine.group("open") is not None
                    else None
                ),
            )
            if routine is not None
            else None
        )
        known_before = (
            routine_key is not None
            and any(
                _routine_name_matches(routine_key, known)
                for known in known_definers
            )
        )
        unsafe_mutation, mutation_offset = _search_path_mutation(
            comments_statement
        )

        if definer and routine and not _safe_search_path(comments_statement):
            unqualified_resolution = (
                create is not None
                and _routine_body_has_unqualified_resolution(
                    comments_statement
                )
            )
            runtime_path_logic = (
                create is not None
                and _routine_body_mentions_search_path(comments_statement)
            )
            requires_body_review = (
                not unsafe_mutation
                and (runtime_path_logic or not unqualified_resolution)
            )
            rule_id = (
                "sql.security-definer-search-path-review"
                if requires_body_review
                else "sql.security-definer-search-path"
            )
            if limiter.allow(rule_id):
                findings.append(
                    _finding_at(
                        rule_id=rule_id,
                        severity=(
                            Severity.MEDIUM
                            if requires_body_review
                            else Severity.CRITICAL
                        ),
                        title=(
                            "SECURITY DEFINER routine needs body-level "
                            "search_path review"
                            if requires_body_review
                            else (
                                "SECURITY DEFINER routine declares an unsafe "
                                "search_path"
                                if unsafe_mutation
                                else "SECURITY DEFINER routine has unsafe "
                                "name-resolution evidence"
                            )
                        ),
                        message=(
                            "No recognized declarative safe search_path is "
                            "present, but "
                            "the available statement does not prove an unqualified "
                            "object or callable lookup. The body may contain "
                            "runtime path logic, "
                            "qualified references, no SQL body, or no body at all. "
                            "Review all object, type, function, and operator "
                            "resolution "
                            "before admission."
                            if requires_body_review
                            else (
                                "A SECURITY DEFINER routine explicitly sets or resets "
                                "search_path without constraining it to trusted "
                                "schemas "
                                "with pg_temp last. Caller-influenced name resolution "
                                "can therefore cross the definer authority boundary."
                                if unsafe_mutation
                                else "A SECURITY DEFINER routine has no recognized "
                                "constrained search_path and contains an unqualified "
                                "object or callable lookup. Caller-influenced "
                                "name resolution can "
                                "therefore cross the definer authority boundary."
                            )
                        ),
                        path=path,
                        text=text,
                        offset=statement_offset + definer.start(),
                        evidence=routine_evidence,
                        capability="database.security-definer",
                        remediation=(
                            "Use only trusted schemas and put pg_temp last, "
                            "for example "
                            "`SET search_path = pg_catalog, pg_temp`; schema-qualify "
                            "every referenced object."
                        ),
                    )
                )

        if (
            alter
            and unsafe_mutation
            and not definer
            and invoker is None
        ):
            rule_id = (
                "sql.security-definer-search-path"
                if known_before
                else "sql.routine-unsafe-search-path"
            )
            if limiter.allow(rule_id):
                findings.append(
                    _finding_at(
                        rule_id=rule_id,
                        severity=(
                            Severity.CRITICAL
                            if known_before
                            else Severity.HIGH
                        ),
                        title=(
                            "SECURITY DEFINER routine loses its safe search_path"
                            if known_before
                            else "Routine ALTER leaves search_path unsafe or unknown"
                        ),
                        message=(
                            "A later ALTER changes or resets search_path on a "
                            "routine previously marked SECURITY DEFINER."
                            if known_before
                            else "The ALTER changes or resets a routine search_path "
                            "without proving that the target is unprivileged."
                        ),
                        path=path,
                        text=text,
                        offset=statement_offset + mutation_offset,
                        evidence=routine_evidence,
                        capability="database.security-definer",
                        remediation=(
                            "Keep the routine's final search_path constrained to "
                            "trusted schemas with pg_temp last; verify the target's "
                            "SECURITY INVOKER/DEFINER state."
                        ),
                    )
                )

        if routine_key is not None and invoker is not None:
            known_definers = {
                known
                for known in known_definers
                if not (
                    _routine_name_matches(routine_key, known)
                    if routine_key[2] == ("wildcard:any-signature",)
                    else _routine_state_matches(routine_key, known)
                )
            }
        if definer and routine_key is not None:
            known_definers.add(routine_key)
            assert routine_evidence is not None
            event_trigger = (
                create is not None
                and _RETURNS_EVENT_TRIGGER.search(configuration_view) is not None
            )
            definer_routines.append(
                (
                    statement_offset,
                    statement_offset + definer.start(),
                    routine_key,
                    routine_evidence,
                    event_trigger,
                )
            )
            if event_trigger and limiter.allow(
                "sql.security-definer-event-trigger"
            ):
                findings.append(
                    _finding_at(
                        rule_id="sql.security-definer-event-trigger",
                        severity=Severity.MEDIUM,
                        title=(
                            "Event-trigger callback crosses a definer authority "
                            "boundary"
                        ),
                        message=(
                            "The SECURITY DEFINER routine returns event_trigger and is "
                            "invoked through separately privileged event-trigger "
                            "registration, not as an ordinary callable API. Review the "
                            "registered events, owner, and DDL authority."
                        ),
                        path=path,
                        text=text,
                        offset=statement_offset + definer.start(),
                        evidence=routine_evidence,
                        capability="database.event-trigger",
                        remediation=(
                            "Keep event-trigger creation restricted, constrain the "
                            "callback search_path, and review its owner and "
                            "event scope."
                        ),
                    )
                )

        grant = _GRANT_ROUTINE_START.match(statement)
        if grant is not None and public_after(statement[grant.end() :], "TO"):
            if limiter.allow("sql.public-execute"):
                grant_keyword = re.search(r"\bGRANT\b", statement, re.IGNORECASE)
                findings.append(
                    _finding_at(
                        rule_id="sql.public-execute",
                        severity=Severity.HIGH,
                        title="Routine execution is granted to PUBLIC",
                        message=(
                            "Every database role receives EXECUTE authority, "
                            "expanding the extension's callable attack surface."
                        ),
                        path=path,
                        text=text,
                        offset=statement_offset
                        + (
                            grant_keyword.start()
                            if grant_keyword
                            else grant.start()
                        ),
                        capability="database.public-execute",
                        remediation=(
                            "REVOKE EXECUTE FROM PUBLIC and grant it only to a "
                            "dedicated, least-privilege role."
                        ),
                    )
                )

        copy_capability = _copy_capability(comments_statement)
        if (
            copy_capability is not None
            and copy_capability[0] == "program"
            and limiter.allow("sql.copy-program")
        ):
            findings.append(
                _finding_at(
                    rule_id="sql.copy-program",
                    severity=Severity.CRITICAL,
                    title="Server-side COPY executes an operating-system command",
                    message=(
                        "COPY ... PROGRAM starts a process with the PostgreSQL server "
                        "account's authority."
                    ),
                    path=path,
                    text=text,
                    offset=statement_offset + copy_capability[1],
                    capability="process.execute",
                    remediation=(
                        "Remove COPY PROGRAM from extension scripts and implement the "
                        "operation in a separately sandboxed, least-privilege service."
                    ),
                )
            )
            continue
        if (
            copy_capability is not None
            and copy_capability[0] == "file"
            and limiter.allow("sql.copy-file")
        ):
            findings.append(
                _finding_at(
                    rule_id="sql.copy-file",
                    severity=Severity.HIGH,
                    title="Server-side COPY reads or writes a filesystem path",
                    message=(
                        "COPY with a quoted path performs filesystem I/O as the "
                        "PostgreSQL server account."
                    ),
                    path=path,
                    text=text,
                    offset=statement_offset + copy_capability[1],
                    capability="filesystem.read-write",
                    remediation=(
                        "Use client-side data transfer or a narrowly scoped external "
                        "service instead of server-side file paths."
                    ),
                )
            )

    for (
        statement_offset,
        definer_offset,
        key,
        routine_evidence,
        event_trigger,
    ) in definer_routines:
        _, routine_name, arguments = key
        wildcard_key = ("routine", routine_name, arguments)
        revoked_offset = max(
            revoked_at.get(key, -1),
            revoked_at.get(wildcard_key, -1),
        )
        if (
            not event_trigger
            and revoked_offset <= statement_offset
            and limiter.allow(
                "sql.security-definer-public-execute"
            )
        ):
            findings.append(
                _finding_at(
                    rule_id="sql.security-definer-public-execute",
                    severity=Severity.HIGH,
                    title="SECURITY DEFINER routine remains executable by PUBLIC",
                    message=(
                        "PostgreSQL grants EXECUTE on new routines to PUBLIC by "
                        "default. This exposes a SECURITY DEFINER authority boundary "
                        "to every role unless a later REVOKE removes that authority; "
                        "the finding does not by itself prove privilege escalation."
                    ),
                    path=path,
                    text=text,
                    offset=definer_offset,
                    evidence=routine_evidence,
                    capability="database.public-execute",
                    remediation=(
                        "Add a later `REVOKE ALL ON FUNCTION/PROCEDURE ... FROM "
                        "PUBLIC` and grant execution only to a least-privilege role."
                    ),
                )
            )

    file_functions = re.compile(
        r"\b(?P<name>pg_read_file|pg_read_binary_file|pg_stat_file|pg_ls_dir|"
        r"pg_ls_logdir|pg_ls_waldir|pg_ls_archive_statusdir)\s*\(",
        re.IGNORECASE,
    )
    for match in file_functions.finditer(masked):
        if not limiter.allow("sql.server-file-function"):
            continue
        findings.append(
            _finding_at(
                rule_id="sql.server-file-function",
                severity=Severity.HIGH,
                title="SQL invokes a server filesystem function",
                message=f"{match.group('name')} exposes PostgreSQL server filesystem metadata or content.",
                path=path,
                text=text,
                offset=match.start(),
                capability="filesystem.read",
                remediation=(
                    "Remove server file access or isolate it behind a reviewed "
                    "least-privilege role with explicit path constraints."
                ),
            )
        )

    quoted_file_functions = re.compile(
        r'(?:(?:"pg_catalog"|pg_catalog)\s*\.\s*)?'
        r'"(?P<name>pg_read_file|pg_read_binary_file|pg_stat_file|pg_ls_dir|'
        r'pg_ls_logdir|pg_ls_waldir|pg_ls_archive_statusdir)"\s*\(',
        re.IGNORECASE,
    )
    for match in quoted_file_functions.finditer(identifier_masked):
        if not limiter.allow("sql.server-file-function"):
            continue
        findings.append(
            _finding_at(
                rule_id="sql.server-file-function",
                severity=Severity.HIGH,
                title="SQL invokes a server filesystem function",
                message=(
                    f"{match.group('name')} exposes PostgreSQL server filesystem "
                    "metadata or content."
                ),
                path=path,
                text=text,
                offset=match.start(),
                capability="filesystem.read",
                remediation=(
                    "Remove server file access or isolate it behind a reviewed "
                    "least-privilege role with explicit path constraints."
                ),
            )
        )

    large_object = re.compile(r"\b(?P<name>lo_import|lo_export)\s*\(", re.IGNORECASE)
    for match in large_object.finditer(masked):
        if not limiter.allow("sql.large-object-file-io"):
            continue
        findings.append(
            _finding_at(
                rule_id="sql.large-object-file-io",
                severity=Severity.HIGH,
                title="Large-object helper accesses a server file",
                message=f"{match.group('name')} transfers data through the PostgreSQL server filesystem.",
                path=path,
                text=text,
                offset=match.start(),
                capability="filesystem.read-write",
                remediation=(
                    "Transfer large objects through the client API rather than "
                    "server-side lo_import/lo_export."
                ),
            )
        )

    for offset, language_name in _untrusted_language_uses(lexical_text):
        if not limiter.allow("sql.untrusted-language"):
            continue
        findings.append(
            _finding_at(
                rule_id="sql.untrusted-language",
                severity=Severity.CRITICAL,
                title="Routine uses an untrusted procedural language",
                message=(
                    f"{language_name} code can escape normal database isolation "
                    "and execute with server-process authority."
                ),
                path=path,
                text=text,
                offset=offset,
                capability="process.native-code",
                remediation=(
                    "Use a trusted language or move the behavior to a separately "
                    "sandboxed service with an explicit database role."
                ),
            )
        )

    external_calls = re.compile(
        r"\b(?P<name>dblink(?:_[A-Za-z0-9_]+)?|"
        r"http_get|http_post|http_put|http_delete|http_head|http|"
        r"net\.http_get|net\.http_post)\s*\(",
        re.IGNORECASE,
    )
    for match in external_calls.finditer(masked):
        if not limiter.allow("sql.external-connection"):
            continue
        findings.append(
            _finding_at(
                rule_id="sql.external-connection",
                severity=Severity.HIGH,
                title="SQL opens an external database or HTTP connection",
                message=f"{match.group('name')} introduces outbound network and data-flow capability.",
                path=path,
                text=text,
                offset=match.start(),
                capability="network.client",
                remediation=(
                    "Remove implicit egress from extension routines or enforce an "
                    "explicit destination allowlist and least-privilege credentials."
                ),
            )
        )

    quoted_external_calls = re.compile(
        r'"(?P<name>dblink(?:_[a-z0-9_]+)?)"\s*\('
    )
    for match in quoted_external_calls.finditer(identifier_masked):
        if not limiter.allow("sql.external-connection"):
            continue
        findings.append(
            _finding_at(
                rule_id="sql.external-connection",
                severity=Severity.HIGH,
                title="SQL opens an external database connection",
                message=(
                    f"{match.group('name')} introduces outbound network and "
                    "data-flow capability."
                ),
                path=path,
                text=text,
                offset=match.start(),
                capability="network.client",
                remediation=(
                    "Remove implicit egress from extension routines or enforce an "
                    "explicit destination allowlist and least-privilege credentials."
                ),
            )
        )
    return limiter.annotate(findings)


@dataclass(frozen=True, slots=True)
class _SourceRule:
    rule_id: str
    severity: Severity
    title: str
    message: str
    capability: str
    remediation: str
    pattern: re.Pattern[str]


_C_RULES = (
    _SourceRule(
        "c.file-io",
        Severity.HIGH,
        "Native extension performs filesystem I/O",
        "Native file APIs run inside the PostgreSQL server process.",
        "filesystem.read-write",
        "Remove host filesystem access or constrain it to a separately sandboxed helper.",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:fopen|freopen|open|openat|creat|unlink|remove|"
            r"rename|opendir|AllocateFile|OpenTransientFile|BasicOpenFile)\s*\("
        ),
    ),
    _SourceRule(
        "c.network",
        Severity.HIGH,
        "Native extension opens network connections",
        "Socket or resolver APIs introduce network capability inside PostgreSQL.",
        "network.client-server",
        "Move network access out of process or enforce explicit destination and protocol policy.",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:socket|connect|bind|listen|accept|accept4|"
            r"getaddrinfo|curl_easy_init|PQconnectdb)\s*\("
        ),
    ),
    _SourceRule(
        "c.process-exec",
        Severity.CRITICAL,
        "Native extension creates or executes processes",
        "Process APIs execute with the PostgreSQL server account's authority.",
        "process.execute",
        "Remove process creation from the extension and delegate it to a sandboxed service.",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:system|popen|fork|vfork|execv|execve|execvp|"
            r"execl|execlp|posix_spawn|posix_spawnp|CreateProcessA|CreateProcessW)\s*\("
        ),
    ),
    _SourceRule(
        "c.dynamic-loading",
        Severity.HIGH,
        "Native extension dynamically loads code",
        "Dynamic loader APIs can bring unreviewed executable code into PostgreSQL.",
        "dynamic-library.load",
        "Link reviewed code at build time or restrict loading to signed, immutable artifacts.",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:dlopen|dlsym|LoadLibraryA|LoadLibraryW|"
            r"DynamicLibraryOpen)\s*\("
        ),
    ),
    _SourceRule(
        "c.background-worker",
        Severity.MEDIUM,
        "Extension registers a PostgreSQL background worker",
        "Background workers are long-lived code executing inside the database server.",
        "process.background-worker",
        "Document worker privileges and lifecycle, minimize capabilities, and add shutdown tests.",
        re.compile(
            r"\b(?:RegisterBackgroundWorker|RegisterDynamicBackgroundWorker)\s*\("
        ),
    ),
)


_RUST_RULES = (
    _SourceRule(
        "rust.file-io",
        Severity.HIGH,
        "Rust extension performs filesystem I/O",
        "Rust filesystem APIs run inside the PostgreSQL server process.",
        "filesystem.read-write",
        "Remove host filesystem access or constrain it to a separately sandboxed helper.",
        re.compile(
            r"\b(?:std::fs(?:::|::[A-Za-z_]+)|fs::(?:read|write|copy|remove|"
            r"rename|create_dir)|File::(?:open|create)|OpenOptions::new)\b"
        ),
    ),
    _SourceRule(
        "rust.network",
        Severity.HIGH,
        "Rust extension opens network connections",
        "Rust networking APIs introduce egress or listener capability inside PostgreSQL.",
        "network.client-server",
        "Move network access out of process or enforce explicit destination and protocol policy.",
        re.compile(
            r"\b(?:std::net(?:::|::[A-Za-z_]+)|TcpStream::connect|"
            r"TcpListener::bind|UdpSocket::bind|reqwest::|hyper::|ureq::)"
        ),
    ),
    _SourceRule(
        "rust.process-exec",
        Severity.CRITICAL,
        "Rust extension creates a child process",
        "Command execution inherits the PostgreSQL server account's authority.",
        "process.execute",
        "Remove child process creation and delegate it to a sandboxed service.",
        re.compile(r"\b(?:std::process::Command|Command::new|process::Command)\b"),
    ),
    _SourceRule(
        "rust.dynamic-loading",
        Severity.HIGH,
        "Rust extension dynamically loads code",
        "Dynamic loading can introduce unreviewed native code into PostgreSQL.",
        "dynamic-library.load",
        "Remove runtime loading or restrict it to signed, immutable artifacts.",
        re.compile(r"\b(?:libloading::|dlopen::|Library::new)\b"),
    ),
    _SourceRule(
        "rust.background-worker",
        Severity.MEDIUM,
        "Rust extension registers a PostgreSQL background worker",
        "Background workers are long-lived code executing inside the database server.",
        "process.background-worker",
        "Document worker privileges and lifecycle, minimize capabilities, and add shutdown tests.",
        re.compile(r"\b(?:BackgroundWorkerBuilder|BackgroundWorker|bgworkers::)\b"),
    ),
    _SourceRule(
        "rust.unsafe",
        Severity.MEDIUM,
        "Rust extension contains an unsafe boundary",
        "Unsafe Rust bypasses compiler-enforced memory-safety guarantees in the database process.",
        "memory.unsafe",
        "Minimize the unsafe block, document invariants, and cover it with sanitizer and fuzz tests.",
        re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b)"),
    ),
)


def _scan_source(
    path: str, text: str, rules: Iterable[_SourceRule], *, rust: bool
) -> list[Finding]:
    masked = mask_c_like(text, rust=rust)
    findings: list[Finding] = []
    for rule in rules:
        matches = rule.pattern.finditer(masked)
        first = next(matches, None)
        if first is None:
            continue
        count = 1
        matched_symbols = {first.group(0).strip()}
        for match in matches:
            count += 1
            if len(matched_symbols) < 8:
                matched_symbols.add(match.group(0).strip())
        evidence = evidence_line(text, first.start())
        if count > 1:
            evidence = (
                f"{evidence} [matched {count} sites: "
                + ", ".join(sorted(matched_symbols))
                + "]"
            )
        findings.append(
            _finding_at(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                message=rule.message,
                path=path,
                text=text,
                offset=first.start(),
                evidence=evidence,
                capability=rule.capability,
                remediation=rule.remediation,
            )
        )
    return findings


def scan_c(path: str, text: str) -> list[Finding]:
    return _scan_source(path, text, _C_RULES, rust=False)


def scan_rust(path: str, text: str) -> list[Finding]:
    return _scan_source(path, text, _RUST_RULES, rust=True)


def _cargo_dependency_names(document: dict[str, object]) -> set[str]:
    names: set[str] = set()

    def collect(section: object) -> None:
        if not isinstance(section, dict):
            return
        for key, value in section.items():
            dependency = str(key).casefold().replace("_", "-")
            if isinstance(value, dict) and isinstance(value.get("package"), str):
                dependency = str(value["package"]).casefold().replace("_", "-")
            names.add(dependency)

    for section_name in (
        "dependencies",
        "build-dependencies",
    ):
        collect(document.get(section_name))
    workspace = document.get("workspace")
    if isinstance(workspace, dict):
        collect(workspace.get("dependencies"))
    target = document.get("target")
    if isinstance(target, dict):
        for target_data in target.values():
            if isinstance(target_data, dict):
                for section_name in (
                    "dependencies",
                    "build-dependencies",
                ):
                    collect(target_data.get(section_name))
    return names


def _dependency_line(text: str, dependency: str) -> int:
    aliases = {dependency, dependency.replace("-", "_")}
    for line_number, line in enumerate(text.splitlines(), start=1):
        for alias in aliases:
            if re.match(rf"^\s*{re.escape(alias)}\s*=", line, re.IGNORECASE):
                return line_number
    return 1


def scan_cargo(path: str, text: str) -> list[Finding]:
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    dependencies = _cargo_dependency_names(document)
    categories = (
        (
            "cargo.network-dependency",
            {"reqwest", "hyper", "ureq", "curl", "isahc", "surf", "awc"},
            "Cargo manifest includes network-capable dependencies",
            "network.client",
            "Remove unnecessary network crates or isolate and constrain their use.",
        ),
        (
            "cargo.process-dependency",
            {"duct", "subprocess", "command-group", "xshell"},
            "Cargo manifest includes process-execution dependencies",
            "process.execute",
            "Remove process helper crates from in-process PostgreSQL extension code.",
        ),
        (
            "cargo.dynamic-loading-dependency",
            {"libloading", "dlopen", "sharedlib"},
            "Cargo manifest includes dynamic-loading dependencies",
            "dynamic-library.load",
            "Prefer build-time linkage to reviewed artifacts over runtime loading.",
        ),
    )
    findings: list[Finding] = []
    for rule_id, candidates, title, capability, remediation in categories:
        matched = sorted(dependencies & candidates)
        if not matched:
            continue
        line = min(_dependency_line(text, item) for item in matched)
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=Severity.MEDIUM,
                title=title,
                message="Detected: " + ", ".join(matched) + ".",
                path=path,
                line=line,
                evidence=", ".join(matched),
                capability=capability,
                remediation=remediation,
            )
        )
    return findings
