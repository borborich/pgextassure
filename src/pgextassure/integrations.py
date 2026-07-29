"""Credential-free vendor projections of verified Admission Event 1.0."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import json
import os
import re
from typing import Any

from .enterprise import (
    ADMISSION_EVENT_SCHEMA_VERSION,
    ADMISSION_EVENT_TYPE,
    _json_bytes,
)
from .signing import MAX_STATEMENT_BYTES, SigningError, _read_regular


INTEGRATION_PROFILES = (
    "jira-cloud-v3",
    "servicenow-change",
    "splunk-hec",
    "elastic-bulk",
)
INTEGRATION_EXPORT_SCHEMA_VERSION = "1.0"
INTEGRATION_EXPORT_TYPE = "pgextassure.integration-export"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_TABLE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_INDEX_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,254}\Z")
_TEXT_LIMIT = 512
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


class IntegrationError(ValueError):
    """An Admission Event or integration projection is malformed."""


class AdmissionEventError(IntegrationError):
    """An Admission Event failed strict validation."""


@dataclass(frozen=True, slots=True)
class IntegrationProjection:
    profile: str
    media_type: str
    payload: bytes
    manifest: bytes
    manifest_document: dict[str, Any]


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IntegrationError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _object(
    value: object,
    *,
    label: str,
    fields: frozenset[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IntegrationError(f"{label} must be an object")
    if set(value) != fields:
        raise IntegrationError(f"{label} has an invalid schema")
    return value


def _text(value: object, *, label: str, maximum: int = _TEXT_LIMIT) -> str:
    if not isinstance(value, str) or not value:
        raise IntegrationError(f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise IntegrationError(f"{label} must be valid UTF-8") from error
    if len(encoded) > maximum:
        raise IntegrationError(f"{label} exceeds the {maximum}-byte limit")
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or ord(character) in _BIDI_CONTROLS
        for character in value
    ):
        raise IntegrationError(f"{label} contains control characters")
    return value


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise IntegrationError(f"{label} is not a SHA-256 digest")
    return value


def _date(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise IntegrationError(f"{label} must use YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise IntegrationError(f"{label} must use YYYY-MM-DD") from error
    if parsed.isoformat() != value:
        raise IntegrationError(f"{label} must use YYYY-MM-DD")
    return value


def _validate_event(document: dict[str, Any]) -> None:
    expected = frozenset(
        {
            "schema_version",
            "event_type",
            "id",
            "observed_on",
            "outcome",
            "active",
            "request",
            "package",
            "decision",
            "trust",
            "subject",
            "signature",
        }
    )
    _object(document, label="Admission Event", fields=expected)
    if (
        document["schema_version"] != ADMISSION_EVENT_SCHEMA_VERSION
        or document["event_type"] != ADMISSION_EVENT_TYPE
    ):
        raise IntegrationError("unsupported Admission Event")
    event_id = _digest(document["id"], label="Admission Event ID")
    _date(document["observed_on"], label="Admission Event observed_on")
    if (
        not isinstance(document["outcome"], str)
        or document["outcome"] not in {"allow", "deny"}
    ):
        raise IntegrationError("Admission Event outcome is invalid")
    if type(document["active"]) is not bool:
        raise IntegrationError("Admission Event active must be a boolean")

    request = _object(
        document["request"],
        label="Admission Event request",
        fields=frozenset({"id", "target", "evaluated_on"}),
    )
    _text(request["id"], label="Admission Event request ID")
    _text(request["target"], label="Admission Event request target")
    _date(request["evaluated_on"], label="Admission Event evaluated_on")

    package = _object(
        document["package"],
        label="Admission Event package",
        fields=frozenset({"digest", "manifest_digest", "files"}),
    )
    _digest(package["digest"], label="Admission Event package digest")
    _digest(
        package["manifest_digest"],
        label="Admission Event package manifest digest",
    )
    if type(package["files"]) is not int or not 1 <= package["files"] <= 64:
        raise IntegrationError("Admission Event package file count is invalid")

    decision = _object(
        document["decision"],
        label="Admission Event decision",
        fields=frozenset({"result", "reasons", "valid_until"}),
    )
    if (
        not isinstance(decision["result"], str)
        or decision["result"] not in {"admit", "deny"}
    ):
        raise IntegrationError("Admission Event decision result is invalid")
    reasons = decision["reasons"]
    if not isinstance(reasons, list) or len(reasons) > 256:
        raise IntegrationError("Admission Event decision reasons are invalid")
    seen_reasons: set[str] = set()
    for index, reason in enumerate(reasons):
        parsed_reason = _text(
            reason,
            label=f"Admission Event decision reason {index}",
        )
        if parsed_reason in seen_reasons:
            raise IntegrationError("Admission Event decision reasons repeat")
        seen_reasons.add(parsed_reason)
    _date(decision["valid_until"], label="Admission Event valid_until")

    trust = _object(
        document["trust"],
        label="Admission Event trust",
        fields=frozenset({"policy_id", "policy_digest"}),
    )
    _text(trust["policy_id"], label="Admission Event policy ID")
    _digest(trust["policy_digest"], label="Admission Event policy digest")

    subject = _object(
        document["subject"],
        label="Admission Event subject",
        fields=frozenset({"digest", "gate", "component", "tool"}),
    )
    _digest(subject["digest"], label="Admission Event subject digest")
    if (
        not isinstance(subject["gate"], str)
        or subject["gate"] not in {"pass", "blocked"}
    ):
        raise IntegrationError("Admission Event subject gate is invalid")
    component = _object(
        subject["component"],
        label="Admission Event component",
        fields=frozenset({"name", "version"}),
    )
    _text(component["name"], label="Admission Event component name")
    if component["version"] is not None:
        _text(component["version"], label="Admission Event component version")
    tool = _object(
        subject["tool"],
        label="Admission Event tool",
        fields=frozenset({"name", "version", "ruleset_version"}),
    )
    if tool["name"] != "pgextassure":
        raise IntegrationError("Admission Event tool name is invalid")
    _text(tool["version"], label="Admission Event tool version")
    _text(tool["ruleset_version"], label="Admission Event ruleset version")

    signature = _object(
        document["signature"],
        label="Admission Event signature",
        fields=frozenset(
            {"signer_id", "public_key_sha256", "created_on"}
        ),
    )
    _text(signature["signer_id"], label="Admission Event signer ID")
    _digest(
        signature["public_key_sha256"],
        label="Admission Event public-key digest",
    )
    _date(signature["created_on"], label="Admission Event signature date")

    if document["active"] != (document["outcome"] == "allow"):
        raise IntegrationError("Admission Event active and outcome disagree")
    if document["active"] and decision["result"] != "admit":
        raise IntegrationError("active Admission Event must contain admit")
    core = {key: value for key, value in document.items() if key != "id"}
    expected_id = "sha256:" + hashlib.sha256(_json_bytes(core)).hexdigest()
    if event_id != expected_id:
        raise IntegrationError("Admission Event ID does not match its content")


def _load_admission_event(
    path: str | os.PathLike[str],
) -> dict[str, Any]:
    try:
        raw = _read_regular(
            path,
            label="Admission Event",
            maximum=MAX_STATEMENT_BYTES,
        )
    except SigningError as error:
        raise IntegrationError(str(error)) from error
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except IntegrationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise IntegrationError(f"invalid Admission Event: {error}") from error
    if not isinstance(parsed, dict):
        raise IntegrationError("Admission Event must be an object")
    _validate_event(parsed)
    if raw != _json_bytes(parsed):
        raise IntegrationError("Admission Event is not canonical JSON")
    return parsed


def load_admission_event(
    path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Load canonical Admission Event 1.0 and recompute its event ID."""

    try:
        return _load_admission_event(path)
    except AdmissionEventError:
        raise
    except IntegrationError as error:
        raise AdmissionEventError(str(error)) from error


def _summary(event: dict[str, Any]) -> str:
    component = event["subject"]["component"]
    version = (
        f" {component['version']}" if component["version"] is not None else ""
    )
    return (
        f"PgExtAssure {event['outcome'].upper()}: "
        f"{component['name']}{version} -> {event['request']['target']}"
    )


def _detail_lines(event: dict[str, Any]) -> list[str]:
    reasons = ", ".join(event["decision"]["reasons"]) or "none"
    return [
        f"Outcome: {event['outcome']}",
        f"Active: {str(event['active']).lower()}",
        f"Request ID: {event['request']['id']}",
        f"Target: {event['request']['target']}",
        f"Event ID: {event['id']}",
        f"Package: {event['package']['digest']}",
        f"Subject: {event['subject']['digest']}",
        f"Trust policy: {event['trust']['policy_digest']}",
        f"Signer key: {event['signature']['public_key_sha256']}",
        f"Valid until: {event['decision']['valid_until']}",
        f"Reasons: {reasons}",
    ]


def _jira(
    event: dict[str, Any],
    *,
    project: str,
    issue_type: str,
) -> bytes:
    if not _NAME_PATTERN.fullmatch(project):
        raise IntegrationError("Jira project key is invalid")
    issue_type = _text(issue_type, label="Jira issue type", maximum=128)
    paragraphs = [
        {
            "type": "paragraph",
            "content": [{"type": "text", "text": line}],
        }
        for line in _detail_lines(event)
    ]
    document = {
        "fields": {
            "project": {"key": project},
            "issuetype": {"name": issue_type},
            "summary": _summary(event)[:255],
            "description": {
                "type": "doc",
                "version": 1,
                "content": paragraphs,
            },
            "labels": [
                "pgextassure",
                "admission-" + event["outcome"],
            ],
        },
        "properties": [
            {
                "key": "pgextassure.admission-event",
                "value": event,
            }
        ],
    }
    return _json_bytes(document)


def _servicenow(event: dict[str, Any], *, table: str) -> bytes:
    if not _TABLE_PATTERN.fullmatch(table):
        raise IntegrationError("ServiceNow table name is invalid")
    document = {
        "short_description": _summary(event)[:160],
        "description": "\n".join(_detail_lines(event)),
        "correlation_id": event["id"],
        "work_notes": (
            "Canonical PgExtAssure Admission Event 1.0:\n"
            + _json_bytes(event).decode("utf-8").rstrip()
        ),
    }
    return _json_bytes(document)


def _splunk(event: dict[str, Any], *, index: str | None) -> bytes:
    document: dict[str, Any] = {
        "source": "pgextassure",
        "sourcetype": "pgextassure:admission",
        "event": event,
        "fields": {
            "event_id": event["id"],
            "outcome": event["outcome"],
            "request_id": event["request"]["id"],
            "target": event["request"]["target"],
        },
    }
    if index is not None:
        document["index"] = _index(index, label="Splunk index")
    return _json_bytes(document)


def _index(value: str, *, label: str) -> str:
    if (
        not _INDEX_PATTERN.fullmatch(value)
        or value in {".", ".."}
        or value[0] in {"_", "-", "+"}
    ):
        raise IntegrationError(f"{label} is invalid")
    return value


def _elastic(event: dict[str, Any], *, index: str) -> bytes:
    index = _index(index, label="Elastic index")
    action = {
        "index": {
            "_index": index,
            "_id": event["id"].removeprefix("sha256:"),
        }
    }
    document = {
        "@timestamp": event["observed_on"] + "T00:00:00Z",
        "pgextassure": event,
    }
    return (
        json.dumps(action, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
        + json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def project_admission_event(
    event_path: str | os.PathLike[str],
    *,
    profile: str,
    project: str | None = None,
    issue_type: str = "Task",
    table: str = "change_request",
    index: str | None = None,
) -> IntegrationProjection:
    """Render one directly sendable, credential-free vendor API payload."""

    if profile not in INTEGRATION_PROFILES:
        raise IntegrationError(f"unsupported integration profile {profile!r}")
    event = load_admission_event(event_path)
    if profile == "jira-cloud-v3":
        if project is None:
            raise IntegrationError("Jira profile requires --project")
        payload = _jira(event, project=project, issue_type=issue_type)
        media_type = "application/json"
        request_path = "/rest/api/3/issue"
    elif profile == "servicenow-change":
        payload = _servicenow(event, table=table)
        media_type = "application/json"
        request_path = f"/api/now/table/{table}"
    elif profile == "splunk-hec":
        payload = _splunk(event, index=index)
        media_type = "application/json"
        request_path = "/services/collector/event"
    else:
        if index is None:
            raise IntegrationError("Elastic profile requires --index")
        payload = _elastic(event, index=index)
        media_type = "application/x-ndjson"
        request_path = "/_bulk"
    manifest_document = {
        "schema_version": INTEGRATION_EXPORT_SCHEMA_VERSION,
        "export_type": INTEGRATION_EXPORT_TYPE,
        "profile": profile,
        "request": {
            "method": "POST",
            "path": request_path,
            "media_type": media_type,
        },
        "payload": {
            "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        },
        "source_event": {
            "id": event["id"],
            "sha256": "sha256:" + hashlib.sha256(
                _json_bytes(event)
            ).hexdigest(),
        },
    }
    return IntegrationProjection(
        profile=profile,
        media_type=media_type,
        payload=payload,
        manifest=_json_bytes(manifest_document),
        manifest_document=manifest_document,
    )
