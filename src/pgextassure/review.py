"""Deterministic, authority-free task packs for assisted security review."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from .grouping import grouped_report_document
from .models import ScanReport
from .source import canonical_json_bytes


REVIEW_PACK_SCHEMA_VERSION = "1.0"
DECISION_LEDGER_SCHEMA_VERSION = "1.0"
MAX_REVIEW_BYTES = 64 * 1024 * 1024
MAX_REVIEW_TASKS = 10_000
MAX_REVIEW_TEXT_BYTES = 4096
REVIEW_DISPOSITIONS = (
    "accepted-capability",
    "actionable-defect",
    "false-positive",
    "unresolved",
)
_DIGEST_PREFIX = "sha256:"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ReviewError(ValueError):
    """A review pack or decision ledger is malformed or does not correlate."""


def _digest(document: object) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        canonical_json_bytes(document)
    ).hexdigest()


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_json(path: str | os.PathLike[str], *, label: str) -> object:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ReviewError(f"cannot inspect {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReviewError(f"{label} must be a non-symlink regular file")
    if metadata.st_size > MAX_REVIEW_BYTES:
        raise ReviewError(f"{label} exceeds the bounded file limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > MAX_REVIEW_BYTES
        ):
            raise ReviewError(f"{label} must remain a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(MAX_REVIEW_BYTES + 1)
    except ReviewError:
        raise
    except OSError as error:
        raise ReviewError(f"cannot read {label}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_REVIEW_BYTES or b"\x00" in raw:
        raise ReviewError(f"{label} exceeds its safe input boundary")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReviewError(f"invalid {label} JSON: {error}") from error


def _exact_object(
    value: object,
    *,
    label: str,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReviewError(f"{label} must be an object")
    keys = frozenset(value)
    if keys - required - optional:
        raise ReviewError(f"{label} contains an unknown field")
    if required - keys:
        raise ReviewError(f"{label} is missing a required field")
    return value


def _bounded_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(f"{label} must be non-empty text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ReviewError(f"{label} must be valid UTF-8") from error
    if len(encoded) > MAX_REVIEW_TEXT_BYTES:
        raise ReviewError(f"{label} exceeds the bounded text limit")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ReviewError(f"{label} contains control characters")
    return value


def review_pack_document(report: ScanReport) -> dict[str, Any]:
    """Create an immutable agent input whose output cannot grant admission."""

    grouped = grouped_report_document(report)
    grouped_digest = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(grouped)).hexdigest()
    )
    tasks = []
    for root_cause in grouped["root_causes"]:
        tasks.append(
            {
                "task_id": root_cause["root_cause_id"],
                "root_cause": root_cause,
                "required_output": {
                    "disposition": list(REVIEW_DISPOSITIONS),
                    "required_fields": [
                        "task_id",
                        "disposition",
                        "rationale",
                        "citations",
                        "reviewer",
                    ],
                },
            }
        )

    document: dict[str, Any] = {
        "schema_version": REVIEW_PACK_SCHEMA_VERSION,
        "review_type": "pgextassure.agent-review-pack",
        "tool": grouped["tool"],
        "subject": {
            "source_manifest_digest": grouped["manifest"]["digest"],
            "grouped_report_digest": grouped_digest,
            "grouping_strategy": grouped["grouping"]["strategy"],
        },
        "coverage": grouped["coverage"],
        "summary": grouped["summary"],
        "authority": {
            "can_grant_admission": False,
            "statement": (
                "Agent output is review assistance only. Admission requires "
                "separate organization policy and authorized human approval."
            ),
        },
        "handling": {
            "source_upload_required": False,
            "contains_source_files": False,
            "may_contain_sensitive_evidence": True,
        },
        "tasks": tasks,
    }
    for name in ("generation", "admission", "policy"):
        if name in grouped:
            document[name] = grouped[name]
    return document


def render_review_pack(report: ScanReport) -> str:
    """Render canonical, human-readable JSON with deterministic bytes."""

    return (
        json.dumps(
            review_pack_document(report),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def load_review_pack(
    path: str | os.PathLike[str],
) -> tuple[dict[str, object], str, tuple[str, ...]]:
    """Load the strict task identity surface of an Agent Review Pack."""

    document = _exact_object(
        _read_json(path, label="review pack"),
        label="review pack",
        required=frozenset(
            {
                "schema_version",
                "review_type",
                "tool",
                "subject",
                "coverage",
                "summary",
                "authority",
                "handling",
                "tasks",
            }
        ),
        optional=frozenset({"generation", "admission", "policy"}),
    )
    if (
        document["schema_version"] != REVIEW_PACK_SCHEMA_VERSION
        or document["review_type"] != "pgextassure.agent-review-pack"
    ):
        raise ReviewError("unsupported review pack contract")
    authority = _exact_object(
        document["authority"],
        label="review pack authority",
        required=frozenset({"can_grant_admission", "statement"}),
    )
    if authority["can_grant_admission"] is not False:
        raise ReviewError("review pack must not grant admission authority")
    subject = _exact_object(
        document["subject"],
        label="review pack subject",
        required=frozenset(
            {
                "source_manifest_digest",
                "grouped_report_digest",
                "grouping_strategy",
            }
        ),
    )
    tasks = document["tasks"]
    if not isinstance(tasks, list) or len(tasks) > MAX_REVIEW_TASKS:
        raise ReviewError("review pack tasks are invalid or exceed the limit")
    task_ids: list[str] = []
    for index, value in enumerate(tasks):
        task = _exact_object(
            value,
            label=f"review task {index}",
            required=frozenset({"task_id", "root_cause", "required_output"}),
        )
        task_id = task["task_id"]
        root_cause = task["root_cause"]
        required_output = _exact_object(
            task["required_output"],
            label=f"review task {index} required output",
            required=frozenset({"disposition", "required_fields"}),
        )
        if (
            not isinstance(task_id, str)
            or not _DIGEST_PATTERN.fullmatch(task_id)
            or not isinstance(root_cause, dict)
            or root_cause.get("root_cause_id") != task_id
            or required_output["disposition"] != list(REVIEW_DISPOSITIONS)
            or required_output["required_fields"]
            != [
                "task_id",
                "disposition",
                "rationale",
                "citations",
                "reviewer",
            ]
        ):
            raise ReviewError(f"review task {index} identity is invalid")
        task_ids.append(task_id)
    if len(set(task_ids)) != len(task_ids):
        raise ReviewError("review pack contains duplicate task identities")
    grouped_digest = subject["grouped_report_digest"]
    if (
        not isinstance(grouped_digest, str)
        or not _DIGEST_PATTERN.fullmatch(grouped_digest)
    ):
        raise ReviewError("review pack grouped report digest is invalid")
    return document, _digest(document), tuple(task_ids)


def decision_template_document(
    review_pack: dict[str, object],
    review_pack_digest: str,
    task_ids: tuple[str, ...],
) -> dict[str, object]:
    subject = review_pack["subject"]
    assert isinstance(subject, dict)
    return {
        "schema_version": DECISION_LEDGER_SCHEMA_VERSION,
        "decision_type": "pgextassure.agent-review-decisions",
        "review_pack_digest": review_pack_digest,
        "grouped_report_digest": subject["grouped_report_digest"],
        "authority": {"can_grant_admission": False},
        "decisions": [
            {
                "task_id": task_id,
                "disposition": "unresolved",
                "rationale": "Pending review.",
                "citations": [],
                "reviewer": "unassigned",
            }
            for task_id in task_ids
        ],
    }


def render_decision_template(path: str | os.PathLike[str]) -> str:
    pack, pack_digest, task_ids = load_review_pack(path)
    return (
        json.dumps(
            decision_template_document(pack, pack_digest, task_ids),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def verify_decision_ledger(
    review_pack_path: str | os.PathLike[str],
    ledger_path: str | os.PathLike[str],
) -> dict[str, object]:
    """Verify exact task coverage and bounded, non-authoritative decisions."""

    pack, pack_digest, task_ids = load_review_pack(review_pack_path)
    ledger = _exact_object(
        _read_json(ledger_path, label="decision ledger"),
        label="decision ledger",
        required=frozenset(
            {
                "schema_version",
                "decision_type",
                "review_pack_digest",
                "grouped_report_digest",
                "authority",
                "decisions",
            }
        ),
    )
    if (
        ledger["schema_version"] != DECISION_LEDGER_SCHEMA_VERSION
        or ledger["decision_type"] != "pgextassure.agent-review-decisions"
        or ledger["review_pack_digest"] != pack_digest
    ):
        raise ReviewError("decision ledger is stale or uses an unsupported contract")
    subject = pack["subject"]
    assert isinstance(subject, dict)
    if ledger["grouped_report_digest"] != subject["grouped_report_digest"]:
        raise ReviewError("decision ledger grouped report digest does not match")
    authority = _exact_object(
        ledger["authority"],
        label="decision ledger authority",
        required=frozenset({"can_grant_admission"}),
    )
    if authority["can_grant_admission"] is not False:
        raise ReviewError("decision ledger must not grant admission authority")
    decisions = ledger["decisions"]
    if not isinstance(decisions, list) or len(decisions) != len(task_ids):
        raise ReviewError("decision ledger must cover every task exactly once")
    seen: set[str] = set()
    counts = {disposition: 0 for disposition in REVIEW_DISPOSITIONS}
    for index, value in enumerate(decisions):
        decision = _exact_object(
            value,
            label=f"decision {index}",
            required=frozenset(
                {"task_id", "disposition", "rationale", "citations", "reviewer"}
            ),
        )
        task_id = decision["task_id"]
        disposition = decision["disposition"]
        if task_id not in task_ids or task_id in seen:
            raise ReviewError(f"decision {index} task identity is invalid")
        if disposition not in REVIEW_DISPOSITIONS:
            raise ReviewError(f"decision {index} disposition is invalid")
        rationale = _bounded_text(
            decision["rationale"],
            label=f"decision {index} rationale",
        )
        reviewer = _bounded_text(
            decision["reviewer"],
            label=f"decision {index} reviewer",
        )
        citations = decision["citations"]
        if not isinstance(citations, list) or len(citations) > 32:
            raise ReviewError(f"decision {index} citations are invalid")
        for citation_index, citation in enumerate(citations):
            _bounded_text(
                citation,
                label=f"decision {index} citation {citation_index}",
            )
        if disposition != "unresolved" and (
            not citations
            or reviewer == "unassigned"
            or rationale == "Pending review."
        ):
            raise ReviewError(
                f"decision {index} resolved disposition lacks review evidence"
            )
        seen.add(task_id)
        counts[disposition] += 1
    if seen != set(task_ids):
        raise ReviewError("decision ledger task set does not match the review pack")
    return {
        "schema_version": DECISION_LEDGER_SCHEMA_VERSION,
        "valid": True,
        "review_pack_digest": pack_digest,
        "grouped_report_digest": subject["grouped_report_digest"],
        "decisions": len(decisions),
        "by_disposition": counts,
        "can_grant_admission": False,
    }
