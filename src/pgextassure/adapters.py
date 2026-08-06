"""Fail-closed normalization of external analyzer output.

The adapter consumes saved analyzer output.  It never invokes an analyzer or
executes extension-controlled code.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from .source import canonical_json_bytes


EXTERNAL_ANALYSIS_SCHEMA_VERSION = "1.0"
EXTERNAL_ANALYSIS_TYPE = "pgextassure.external-analysis"
PGSPOT_ADAPTER_NAME = "pgextassure.pgspot-text"
PGSPOT_ADAPTER_VERSION = "1.0"
PGSPOT_INFORMATION_URI = "https://github.com/timescale/pgspot"
SUPPORTED_PGSPOT_VERSION = "0.9.2"
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_STDOUT_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_DIAGNOSTICS = 10_000
MAX_TEXT_BYTES = 4096

_DIAGNOSTIC = re.compile(
    r"^(PS[0-9]{3}): (.+?): (.*) at line ([1-9][0-9]{0,7})$"
)
_SUMMARY = re.compile(
    r"^(?P<file_space> ?)Errors: (?P<errors>[0-9]{1,5}) "
    r"Warnings: (?P<warnings>[0-9]{1,5}) "
    r"Unknown: (?P<unknown>[0-9]{1,5})(?P=file_space)$"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LEVELS = {
    **{
        code: "warning"
        for code in ("PS001", "PS002", "PS005", "PS006", "PS016")
    },
    **{
        code: "error"
        for code in (
            "PS003",
            "PS004",
            "PS007",
            "PS009",
            "PS010",
            "PS011",
            "PS012",
            "PS013",
            "PS014",
            "PS015",
            "PS017",
            "PS018",
        )
    },
}
_BIDI_CONTROLS = frozenset(
    {
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    }
)


class ExternalAnalysisError(ValueError):
    """External analyzer evidence is malformed or cannot be correlated."""


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExternalAnalysisError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_regular(
    path: str | os.PathLike[str],
    *,
    label: str,
    maximum: int,
) -> bytes:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ExternalAnalysisError(f"cannot inspect {label}: {error}") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > maximum
    ):
        raise ExternalAnalysisError(
            f"{label} must be a bounded non-symlink regular file"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum:
            raise ExternalAnalysisError(
                f"{label} must remain a bounded regular file"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(maximum + 1)
    except ExternalAnalysisError:
        raise
    except OSError as error:
        raise ExternalAnalysisError(f"cannot read {label}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > maximum or b"\x00" in raw:
        raise ExternalAnalysisError(f"{label} exceeds its safe input boundary")
    return raw


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _text(
    value: object,
    *,
    label: str,
    maximum: int = MAX_TEXT_BYTES,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        qualifier = "text" if allow_empty else "non-empty text"
        raise ExternalAnalysisError(f"{label} must be {qualifier}")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ExternalAnalysisError(f"{label} must be valid UTF-8") from error
    if len(encoded) > maximum:
        raise ExternalAnalysisError(f"{label} exceeds the bounded text limit")
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or ord(character) in _BIDI_CONTROLS
        for character in value
    ):
        raise ExternalAnalysisError(f"{label} contains control characters")
    return value


def _source_path(value: object) -> str:
    path = _text(value, label="subject path", maximum=1024)
    if "\\" in path or path.startswith("/"):
        raise ExternalAnalysisError("subject path must be a relative POSIX path")
    parsed = PurePosixPath(path)
    if parsed.as_posix() != path or path == "." or ".." in parsed.parts:
        raise ExternalAnalysisError("subject path must be a normalized relative path")
    return path


def _decode_stdout(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ExternalAnalysisError("pgspot stdout must be valid UTF-8") from error
    if "\r" in text.replace("\r\n", ""):
        raise ExternalAnalysisError("pgspot stdout contains an unsupported line ending")
    for character in text:
        codepoint = ord(character)
        if character not in {"\r", "\n"} and (
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or codepoint in _BIDI_CONTROLS
        ):
            raise ExternalAnalysisError("pgspot stdout contains control characters")
    return text


def _parse_pgspot_stdout(raw: bytes) -> tuple[list[dict[str, Any]], dict[str, int]]:
    text = _decode_stdout(raw)
    diagnostics: list[dict[str, Any]] = []
    summary: dict[str, int] | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        summary_match = _SUMMARY.fullmatch(line)
        if summary_match:
            if summary is not None:
                raise ExternalAnalysisError("pgspot stdout contains multiple summaries")
            summary = {
                "errors": int(summary_match.group("errors")),
                "warnings": int(summary_match.group("warnings")),
                "unknown": int(summary_match.group("unknown")),
            }
            continue
        if summary is not None:
            raise ExternalAnalysisError("pgspot stdout contains content after its summary")
        match = _DIAGNOSTIC.fullmatch(line)
        if not match:
            raise ExternalAnalysisError(
                f"unrecognized pgspot stdout line {line_number}"
            )
        code, title, message, source_line = match.groups()
        level = _LEVELS.get(code)
        if level is None:
            raise ExternalAnalysisError(f"unsupported pgspot rule {code}")
        parsed_source_line = int(source_line)
        if parsed_source_line > MAX_SOURCE_BYTES + 1:
            raise ExternalAnalysisError(f"unsupported pgspot line for {code}")
        diagnostics.append(
            {
                "rule_id": f"pgspot.{code}",
                "native_rule_id": code,
                "level": level,
                "title": _text(title, label=f"{code} title"),
                "message": _text(
                    message,
                    label=f"{code} message",
                    allow_empty=True,
                ),
                "line": parsed_source_line,
            }
        )
        if len(diagnostics) > MAX_DIAGNOSTICS:
            raise ExternalAnalysisError("pgspot stdout exceeds the diagnostic limit")
    if summary is None:
        raise ExternalAnalysisError("pgspot stdout is missing its summary")
    if summary["unknown"] != 0:
        raise ExternalAnalysisError("pgspot reported unknown diagnostics")
    observed = {
        "errors": sum(item["level"] == "error" for item in diagnostics),
        "warnings": sum(item["level"] == "warning" for item in diagnostics),
    }
    if any(summary[key] != observed[key] for key in observed):
        raise ExternalAnalysisError(
            "pgspot summary does not match parsed diagnostics"
        )
    summary["diagnostics"] = len(diagnostics)
    return diagnostics, summary


def normalize_pgspot(
    source_path: str | os.PathLike[str],
    stdout_path: str | os.PathLike[str],
    *,
    subject_path: str,
    analyzer_version: str,
    exit_code: int,
) -> dict[str, Any]:
    """Normalize one pgspot 0.9.2 single-file text result."""

    if analyzer_version != SUPPORTED_PGSPOT_VERSION:
        raise ExternalAnalysisError(
            f"unsupported pgspot version {analyzer_version!r}; "
            f"expected {SUPPORTED_PGSPOT_VERSION}"
        )
    if type(exit_code) is not int or exit_code not in {0, 1}:
        raise ExternalAnalysisError("pgspot exit code must be 0 or 1")
    normalized_path = _source_path(subject_path)
    source = _read_regular(
        source_path,
        label="source SQL",
        maximum=MAX_SOURCE_BYTES,
    )
    stdout = _read_regular(
        stdout_path,
        label="pgspot stdout",
        maximum=MAX_STDOUT_BYTES,
    )
    diagnostics, summary = _parse_pgspot_stdout(stdout)
    expected_exit = 1 if summary["diagnostics"] else 0
    if exit_code != expected_exit:
        raise ExternalAnalysisError(
            "pgspot exit code does not match its normalized result"
        )
    for diagnostic in diagnostics:
        diagnostic["path"] = normalized_path
    return {
        "schema_version": EXTERNAL_ANALYSIS_SCHEMA_VERSION,
        "document_type": EXTERNAL_ANALYSIS_TYPE,
        "adapter": {
            "name": PGSPOT_ADAPTER_NAME,
            "version": PGSPOT_ADAPTER_VERSION,
        },
        "analyzer": {
            "name": "pgspot",
            "version": analyzer_version,
            "version_evidence": "declared",
            "information_uri": PGSPOT_INFORMATION_URI,
        },
        "subject": {
            "path": normalized_path,
            "size": len(source),
            "sha256": _sha256(source),
        },
        "input": {
            "format": "pgspot-text-v0.9.2",
            "exit_code": exit_code,
            "stdout_size": len(stdout),
            "stdout_sha256": _sha256(stdout),
        },
        "summary": summary,
        "diagnostics": diagnostics,
    }


def render_external_analysis(document: dict[str, Any]) -> bytes:
    """Return the canonical stored representation, including one final LF."""

    return canonical_json_bytes(document) + b"\n"


def _object(value: object, *, label: str, fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise ExternalAnalysisError(f"{label} has an invalid schema")
    return value


def _validate_document(document: object) -> dict[str, Any]:
    root = _object(
        document,
        label="external analysis",
        fields=frozenset(
            {
                "schema_version",
                "document_type",
                "adapter",
                "analyzer",
                "subject",
                "input",
                "summary",
                "diagnostics",
            }
        ),
    )
    if (
        root["schema_version"] != EXTERNAL_ANALYSIS_SCHEMA_VERSION
        or root["document_type"] != EXTERNAL_ANALYSIS_TYPE
    ):
        raise ExternalAnalysisError("unsupported external analysis document")
    adapter = _object(
        root["adapter"],
        label="adapter",
        fields=frozenset({"name", "version"}),
    )
    if adapter != {"name": PGSPOT_ADAPTER_NAME, "version": PGSPOT_ADAPTER_VERSION}:
        raise ExternalAnalysisError("unsupported external analysis adapter")
    analyzer = _object(
        root["analyzer"],
        label="analyzer",
        fields=frozenset({"name", "version", "version_evidence", "information_uri"}),
    )
    if analyzer != {
        "name": "pgspot",
        "version": SUPPORTED_PGSPOT_VERSION,
        "version_evidence": "declared",
        "information_uri": PGSPOT_INFORMATION_URI,
    }:
        raise ExternalAnalysisError("unsupported external analyzer declaration")
    subject = _object(
        root["subject"],
        label="subject",
        fields=frozenset({"path", "size", "sha256"}),
    )
    _source_path(subject["path"])
    if (
        type(subject["size"]) is not int
        or not 0 <= subject["size"] <= MAX_SOURCE_BYTES
    ):
        raise ExternalAnalysisError("subject size is invalid")
    if (
        not isinstance(subject["sha256"], str)
        or not _DIGEST.fullmatch(subject["sha256"])
    ):
        raise ExternalAnalysisError("subject digest is invalid")
    input_data = _object(
        root["input"],
        label="input",
        fields=frozenset({"format", "exit_code", "stdout_size", "stdout_sha256"}),
    )
    if input_data["format"] != "pgspot-text-v0.9.2":
        raise ExternalAnalysisError("external analysis input format is invalid")
    if (
        type(input_data["exit_code"]) is not int
        or input_data["exit_code"] not in {0, 1}
    ):
        raise ExternalAnalysisError("external analysis exit code is invalid")
    if (
        type(input_data["stdout_size"]) is not int
        or not 0 <= input_data["stdout_size"] <= MAX_STDOUT_BYTES
    ):
        raise ExternalAnalysisError("external analysis stdout size is invalid")
    if (
        not isinstance(input_data["stdout_sha256"], str)
        or not _DIGEST.fullmatch(input_data["stdout_sha256"])
    ):
        raise ExternalAnalysisError("external analysis stdout digest is invalid")
    summary = _object(
        root["summary"],
        label="summary",
        fields=frozenset({"diagnostics", "errors", "warnings", "unknown"}),
    )
    for name in ("diagnostics", "errors", "warnings", "unknown"):
        value = summary[name]
        if type(value) is not int or not 0 <= value <= MAX_DIAGNOSTICS:
            raise ExternalAnalysisError(f"external analysis {name} count is invalid")
    if summary["unknown"] != 0:
        raise ExternalAnalysisError("external analysis unknown count must be zero")
    if (
        not isinstance(root["diagnostics"], list)
        or len(root["diagnostics"]) > MAX_DIAGNOSTICS
    ):
        raise ExternalAnalysisError("external analysis diagnostics are invalid")
    observed_errors = 0
    observed_warnings = 0
    for index, value in enumerate(root["diagnostics"]):
        diagnostic = _object(
            value,
            label=f"diagnostic {index}",
            fields=frozenset(
                {
                    "rule_id",
                    "native_rule_id",
                    "level",
                    "title",
                    "message",
                    "path",
                    "line",
                }
            ),
        )
        native_rule_id = diagnostic["native_rule_id"]
        if not isinstance(native_rule_id, str) or native_rule_id not in _LEVELS:
            raise ExternalAnalysisError(f"diagnostic {index} rule is invalid")
        expected_level = _LEVELS[native_rule_id]
        if (
            diagnostic["rule_id"] != f"pgspot.{native_rule_id}"
            or diagnostic["level"] != expected_level
        ):
            raise ExternalAnalysisError(
                f"diagnostic {index} normalization is inconsistent"
            )
        _text(diagnostic["title"], label=f"diagnostic {index} title")
        _text(
            diagnostic["message"],
            label=f"diagnostic {index} message",
            allow_empty=True,
        )
        if diagnostic["path"] != subject["path"]:
            raise ExternalAnalysisError(f"diagnostic {index} path is inconsistent")
        if (
            type(diagnostic["line"]) is not int
            or not 1 <= diagnostic["line"] <= MAX_SOURCE_BYTES + 1
        ):
            raise ExternalAnalysisError(f"diagnostic {index} line is invalid")
        if expected_level == "error":
            observed_errors += 1
        else:
            observed_warnings += 1
    if (
        summary["diagnostics"] != len(root["diagnostics"])
        or summary["errors"] != observed_errors
        or summary["warnings"] != observed_warnings
    ):
        raise ExternalAnalysisError("external analysis summary is inconsistent")
    expected_exit = 1 if root["diagnostics"] else 0
    if input_data["exit_code"] != expected_exit:
        raise ExternalAnalysisError("external analysis exit code is inconsistent")
    return root


def load_external_analysis(path: str | os.PathLike[str]) -> dict[str, Any]:
    raw = _read_regular(
        path,
        label="external analysis document",
        maximum=MAX_DOCUMENT_BYTES,
    )
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ExternalAnalysisError(f"invalid external analysis JSON: {error}") from error
    document = _validate_document(parsed)
    if raw != render_external_analysis(document):
        raise ExternalAnalysisError("external analysis document is not canonical JSON")
    return document


def verify_external_analysis(
    document_path: str | os.PathLike[str],
    source_path: str | os.PathLike[str],
    stdout_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Rebuild a normalized document from its exact evidence and compare it."""

    document = load_external_analysis(document_path)
    rebuilt = normalize_pgspot(
        source_path,
        stdout_path,
        subject_path=document["subject"]["path"],
        analyzer_version=document["analyzer"]["version"],
        exit_code=document["input"]["exit_code"],
    )
    if document != rebuilt:
        raise ExternalAnalysisError(
            "external analysis does not match the supplied source and stdout"
        )
    return document
