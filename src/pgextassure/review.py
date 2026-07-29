"""Deterministic, authority-free task packs for assisted security review."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .grouping import grouped_report_document
from .models import ScanReport
from .source import canonical_json_bytes


REVIEW_PACK_SCHEMA_VERSION = "1.0"
REVIEW_DISPOSITIONS = (
    "accepted-capability",
    "actionable-defect",
    "false-positive",
    "unresolved",
)


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
