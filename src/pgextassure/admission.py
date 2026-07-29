"""Reviewable baselines and expiring root-cause suppressions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from .grouping import RootCauseGroup, group_findings
from .models import SEVERITY_RANK, ScanReport, Severity


MAX_ADMISSION_FILE_BYTES = 1024 * 1024
MAX_ADMISSION_ENTRIES = 10_000
MAX_OWNER_BYTES = 256
MAX_REASON_BYTES = 4096
MAX_TICKET_BYTES = 512
_ROOT_CAUSE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RULE_ID_PATTERN = re.compile(r"[a-z][a-z0-9.-]{0,127}\Z")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
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


class AdmissionError(ValueError):
    """An admission-state file is malformed, stale, or unsafe."""


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    root_cause_id: str
    rule_id: str
    severity: Severity


@dataclass(frozen=True, slots=True)
class Baseline:
    digest: str
    created_on: date
    tool_version: str
    ruleset_version: str
    source_manifest_digest: str
    generation_plan_digest: str | None
    entries: tuple[BaselineEntry, ...]


@dataclass(frozen=True, slots=True)
class Suppression:
    root_cause_id: str
    rule_id: str
    severity: Severity
    owner: str
    reason: str
    expires_on: date
    ticket: str | None


@dataclass(frozen=True, slots=True)
class SuppressionSet:
    digest: str
    ruleset_version: str
    entries: tuple[Suppression, ...]


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _object(
    value: object,
    *,
    label: str,
    allowed: frozenset[str],
    required: frozenset[str],
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AdmissionError(f"{label} must be an object")
    keys = frozenset(value)
    unknown = keys - allowed
    missing = required - keys
    if unknown:
        raise AdmissionError(
            f"{label} contains unknown field {sorted(unknown)[0]!r}"
        )
    if missing:
        raise AdmissionError(
            f"{label} is missing field {sorted(missing)[0]!r}"
        )
    return value


def _bounded_text(
    value: object,
    *,
    label: str,
    maximum: int,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdmissionError(f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise AdmissionError(f"{label} must be valid UTF-8") from error
    if len(encoded) > maximum:
        raise AdmissionError(f"{label} exceeds the {maximum}-byte limit")
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or ord(character) in _BIDI_CONTROLS
        for character in value
    ):
        raise AdmissionError(f"{label} contains control characters")
    return value


def parse_admission_date(value: object, *, label: str) -> date:
    if not isinstance(value, str):
        raise AdmissionError(f"{label} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise AdmissionError(f"{label} must be an ISO date") from error
    if parsed.isoformat() != value:
        raise AdmissionError(f"{label} must use YYYY-MM-DD")
    return parsed


def _read_json_file(
    path: str | os.PathLike[str],
    *,
    label: str,
) -> tuple[bytes, object]:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise AdmissionError(f"cannot inspect {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise AdmissionError(f"{label} must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise AdmissionError(f"{label} must be a regular file")
    if metadata.st_size > MAX_ADMISSION_FILE_BYTES:
        raise AdmissionError(
            f"{label} exceeds the {MAX_ADMISSION_FILE_BYTES}-byte limit"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise AdmissionError(f"{label} must remain a regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(MAX_ADMISSION_FILE_BYTES + 1)
    except AdmissionError:
        raise
    except OSError as error:
        raise AdmissionError(f"cannot read {label}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_ADMISSION_FILE_BYTES:
        raise AdmissionError(
            f"{label} exceeds the {MAX_ADMISSION_FILE_BYTES}-byte limit"
        )
    if b"\x00" in raw:
        raise AdmissionError(f"{label} contains binary data")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdmissionError(f"{label} is not UTF-8") from error
    try:
        parsed = json.loads(text, object_pairs_hook=_pairs_object)
    except AdmissionError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise AdmissionError(f"invalid {label} JSON: {error}") from error
    return raw, parsed


def _root_cause_entry(
    value: object,
    *,
    label: str,
    allowed: frozenset[str],
    required: frozenset[str],
) -> tuple[dict[str, object], str, str, Severity]:
    item = _object(
        value,
        label=label,
        allowed=allowed,
        required=required,
    )
    root_cause_id = item["root_cause_id"]
    if (
        not isinstance(root_cause_id, str)
        or not _ROOT_CAUSE_PATTERN.fullmatch(root_cause_id)
    ):
        raise AdmissionError(f"{label} root_cause_id is invalid")
    rule_id = item["rule_id"]
    if not isinstance(rule_id, str) or not _RULE_ID_PATTERN.fullmatch(rule_id):
        raise AdmissionError(f"{label} rule_id is invalid")
    try:
        severity = Severity(item["severity"])
    except (TypeError, ValueError) as error:
        raise AdmissionError(f"{label} severity is invalid") from error
    return item, root_cause_id, rule_id, severity


def load_baseline(path: str | os.PathLike[str]) -> Baseline:
    """Load a strict root-cause baseline without accepting wildcard entries."""

    raw, parsed = _read_json_file(path, label="baseline")
    document = _object(
        parsed,
        label="baseline",
        allowed=frozenset(
            {"schema_version", "created_on", "tool", "source", "root_causes"}
        ),
        required=frozenset(
            {"schema_version", "created_on", "tool", "source", "root_causes"}
        ),
    )
    if document["schema_version"] != "1.0":
        raise AdmissionError("baseline schema_version must be '1.0'")
    created_on = parse_admission_date(
        document["created_on"],
        label="baseline created_on",
    )
    tool = _object(
        document["tool"],
        label="baseline tool",
        allowed=frozenset({"name", "version", "ruleset_version"}),
        required=frozenset({"name", "version", "ruleset_version"}),
    )
    if tool["name"] != "pgextassure":
        raise AdmissionError("baseline tool name must be 'pgextassure'")
    tool_version = _bounded_text(
        tool["version"],
        label="baseline tool version",
        maximum=128,
    )
    ruleset_version = _bounded_text(
        tool["ruleset_version"],
        label="baseline ruleset version",
        maximum=128,
    )
    source = _object(
        document["source"],
        label="baseline source",
        allowed=frozenset(
            {"manifest_digest", "generation_plan_digest"}
        ),
        required=frozenset({"manifest_digest"}),
    )
    manifest_digest = source["manifest_digest"]
    if (
        not isinstance(manifest_digest, str)
        or not _DIGEST_PATTERN.fullmatch(manifest_digest)
    ):
        raise AdmissionError("baseline source manifest_digest is invalid")
    generation_digest = source.get("generation_plan_digest")
    if generation_digest is not None and (
        not isinstance(generation_digest, str)
        or not _DIGEST_PATTERN.fullmatch(generation_digest)
    ):
        raise AdmissionError(
            "baseline source generation_plan_digest is invalid"
        )
    raw_entries = document["root_causes"]
    if not isinstance(raw_entries, list):
        raise AdmissionError("baseline root_causes must be a list")
    if len(raw_entries) > MAX_ADMISSION_ENTRIES:
        raise AdmissionError(
            f"baseline exceeds the {MAX_ADMISSION_ENTRIES}-entry limit"
        )
    entries: list[BaselineEntry] = []
    seen: set[str] = set()
    fields = frozenset({"root_cause_id", "rule_id", "severity"})
    for index, value in enumerate(raw_entries):
        _item, root_id, rule_id, severity = _root_cause_entry(
            value,
            label=f"baseline root cause {index}",
            allowed=fields,
            required=fields,
        )
        if root_id in seen:
            raise AdmissionError(f"baseline repeats root cause {root_id!r}")
        seen.add(root_id)
        entries.append(BaselineEntry(root_id, rule_id, severity))
    return Baseline(
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        created_on=created_on,
        tool_version=tool_version,
        ruleset_version=ruleset_version,
        source_manifest_digest=manifest_digest,
        generation_plan_digest=generation_digest,
        entries=tuple(entries),
    )


def load_suppressions(path: str | os.PathLike[str]) -> SuppressionSet:
    """Load exact, owner-attributed, expiring root-cause suppressions."""

    raw, parsed = _read_json_file(path, label="suppressions")
    document = _object(
        parsed,
        label="suppressions",
        allowed=frozenset(
            {"schema_version", "ruleset_version", "suppressions"}
        ),
        required=frozenset(
            {"schema_version", "ruleset_version", "suppressions"}
        ),
    )
    if document["schema_version"] != "1.0":
        raise AdmissionError("suppressions schema_version must be '1.0'")
    ruleset_version = _bounded_text(
        document["ruleset_version"],
        label="suppressions ruleset_version",
        maximum=128,
    )
    raw_entries = document["suppressions"]
    if not isinstance(raw_entries, list):
        raise AdmissionError("suppressions must be a list")
    if len(raw_entries) > MAX_ADMISSION_ENTRIES:
        raise AdmissionError(
            f"suppressions exceed the {MAX_ADMISSION_ENTRIES}-entry limit"
        )
    entries: list[Suppression] = []
    seen: set[str] = set()
    required = frozenset(
        {
            "root_cause_id",
            "rule_id",
            "severity",
            "owner",
            "reason",
            "expires_on",
        }
    )
    allowed = required | {"ticket"}
    for index, value in enumerate(raw_entries):
        item, root_id, rule_id, severity = _root_cause_entry(
            value,
            label=f"suppression {index}",
            allowed=allowed,
            required=required,
        )
        if root_id in seen:
            raise AdmissionError(f"suppressions repeat root cause {root_id!r}")
        seen.add(root_id)
        owner = _bounded_text(
            item["owner"],
            label=f"suppression {index} owner",
            maximum=MAX_OWNER_BYTES,
        )
        reason = _bounded_text(
            item["reason"],
            label=f"suppression {index} reason",
            maximum=MAX_REASON_BYTES,
        )
        ticket_value = item.get("ticket")
        ticket = (
            _bounded_text(
                ticket_value,
                label=f"suppression {index} ticket",
                maximum=MAX_TICKET_BYTES,
            )
            if ticket_value is not None
            else None
        )
        expires_on = parse_admission_date(
            item["expires_on"],
            label=f"suppression {index} expires_on",
        )
        entries.append(
            Suppression(
                root_cause_id=root_id,
                rule_id=rule_id,
                severity=severity,
                owner=owner,
                reason=reason,
                expires_on=expires_on,
                ticket=ticket,
            )
        )
    return SuppressionSet(
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        ruleset_version=ruleset_version,
        entries=tuple(entries),
    )


def _verify_entry(
    group: RootCauseGroup,
    *,
    rule_id: str,
    severity: Severity,
    label: str,
) -> None:
    if group.rule_id != rule_id or group.severity is not severity:
        raise AdmissionError(
            f"{label} metadata does not match root cause "
            f"{group.root_cause_id!r}"
        )


def create_baseline_document(
    report: ScanReport,
    *,
    created_on: date,
) -> dict[str, Any]:
    """Create a deterministic baseline snapshot from all current root causes."""

    source: dict[str, str] = {
        "manifest_digest": report.manifest.digest,
    }
    if report.generation is not None:
        source["generation_plan_digest"] = report.generation["plan"]["digest"]
    return {
        "schema_version": "1.0",
        "created_on": created_on.isoformat(),
        "tool": dict(report.tool),
        "source": source,
        "root_causes": [
            {
                "root_cause_id": group.root_cause_id,
                "rule_id": group.rule_id,
                "severity": group.severity.value,
            }
            for group in group_findings(report.findings)
        ],
    }


def render_baseline(report: ScanReport, *, created_on: date) -> str:
    return (
        json.dumps(
            create_baseline_document(report, created_on=created_on),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def apply_admission(
    report: ScanReport,
    *,
    baseline: Baseline | None = None,
    suppressions: SuppressionSet | None = None,
    evaluated_on: date | None = None,
) -> ScanReport:
    """Attach auditable dispositions while retaining every original finding."""

    if baseline is None and suppressions is None:
        return report
    ruleset_version = report.tool["ruleset_version"]
    if baseline is not None and baseline.ruleset_version != ruleset_version:
        raise AdmissionError(
            "baseline ruleset_version does not match the scanner ruleset"
        )
    if (
        suppressions is not None
        and suppressions.ruleset_version != ruleset_version
    ):
        raise AdmissionError(
            "suppressions ruleset_version does not match the scanner ruleset"
        )
    if suppressions is not None and evaluated_on is None:
        raise AdmissionError(
            "an evaluation date is required when suppressions are used"
        )

    baseline_entries = {
        entry.root_cause_id: entry
        for entry in (() if baseline is None else baseline.entries)
    }
    suppression_entries = {
        entry.root_cause_id: entry
        for entry in (() if suppressions is None else suppressions.entries)
    }
    overlap = set(baseline_entries) & set(suppression_entries)
    if overlap:
        raise AdmissionError(
            "baseline and suppressions overlap at root cause "
            f"{sorted(overlap)[0]!r}"
        )

    decisions: list[dict[str, Any]] = []
    matched_baseline: set[str] = set()
    matched_suppressions: set[str] = set()
    counts = {
        "active": 0,
        "baselined": 0,
        "suppressed": 0,
        "expired": 0,
    }
    for group in group_findings(report.findings):
        decision: dict[str, Any] = {
            "root_cause_id": group.root_cause_id,
            "rule_id": group.rule_id,
            "severity": group.severity.value,
            "status": "active",
        }
        baseline_entry = baseline_entries.get(group.root_cause_id)
        suppression = suppression_entries.get(group.root_cause_id)
        if baseline_entry is not None:
            _verify_entry(
                group,
                rule_id=baseline_entry.rule_id,
                severity=baseline_entry.severity,
                label="baseline",
            )
            decision["status"] = "baselined"
            matched_baseline.add(group.root_cause_id)
        elif suppression is not None:
            _verify_entry(
                group,
                rule_id=suppression.rule_id,
                severity=suppression.severity,
                label="suppression",
            )
            assert evaluated_on is not None
            status = (
                "expired"
                if suppression.expires_on < evaluated_on
                else "suppressed"
            )
            decision.update(
                {
                    "status": status,
                    "owner": suppression.owner,
                    "reason": suppression.reason,
                    "expires_on": suppression.expires_on.isoformat(),
                }
            )
            if suppression.ticket is not None:
                decision["ticket"] = suppression.ticket
            matched_suppressions.add(group.root_cause_id)
        counts[decision["status"]] += 1
        decisions.append(decision)

    admission: dict[str, Any] = {
        "schema_version": "1.0",
        "summary": {
            "root_causes": len(decisions),
            **counts,
        },
        "decisions": decisions,
    }
    if evaluated_on is not None:
        admission["evaluated_on"] = evaluated_on.isoformat()
    if baseline is not None:
        baseline_metadata: dict[str, Any] = {
            "digest": baseline.digest,
            "created_on": baseline.created_on.isoformat(),
            "tool_version": baseline.tool_version,
            "ruleset_version": baseline.ruleset_version,
            "source_manifest_digest": baseline.source_manifest_digest,
            "matched": len(matched_baseline),
            "stale": len(baseline.entries) - len(matched_baseline),
        }
        if baseline.generation_plan_digest is not None:
            baseline_metadata["generation_plan_digest"] = (
                baseline.generation_plan_digest
            )
        admission["baseline"] = baseline_metadata
    if suppressions is not None:
        admission["suppressions"] = {
            "digest": suppressions.digest,
            "ruleset_version": suppressions.ruleset_version,
            "matched": len(matched_suppressions),
            "unused": len(suppressions.entries) - len(matched_suppressions),
        }
    return replace(
        report,
        admission=admission,
    )


def gate_root_causes(
    report: ScanReport,
    *,
    minimum_severity: Severity,
) -> tuple[str, ...]:
    """Return active or expired root causes that reach a gate threshold."""

    if report.admission is None:
        return ()
    minimum_rank = SEVERITY_RANK[minimum_severity]
    return tuple(
        decision["root_cause_id"]
        for decision in report.admission["decisions"]
        if decision["status"] in {"active", "expired"}
        and SEVERITY_RANK[Severity(decision["severity"])] >= minimum_rank
    )


def decision_map(report: ScanReport) -> dict[str, dict[str, Any]]:
    """Return admission decisions keyed by root-cause ID."""

    if report.admission is None:
        return {}
    return {
        decision["root_cause_id"]: decision
        for decision in report.admission["decisions"]
    }
