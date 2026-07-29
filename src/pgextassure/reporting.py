"""Deterministic text, JSON, and SARIF 2.1 reporters."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from .admission import decision_map
from .grouping import (
    group_findings,
    grouped_report_document,
    root_cause_id_for_finding,
)
from .models import Finding, ScanReport, Severity
from .source import canonical_json_bytes


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


def sanitize_terminal_text(value: object) -> str:
    """Escape terminal controls in hostile paths, evidence, and errors."""

    output: list[str] = []
    for character in str(value):
        codepoint = ord(character)
        if (
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or 0xD800 <= codepoint <= 0xDFFF
            or codepoint in _BIDI_CONTROLS
        ):
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(character)
    return "".join(output)


def render_json(report: ScanReport) -> str:
    return json.dumps(
        report.to_dict(),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    ) + "\n"


def render_grouped_json(report: ScanReport) -> str:
    return json.dumps(
        grouped_report_document(report),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    ) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _fingerprint(finding: Finding) -> str:
    return hashlib.sha256(canonical_json_bytes(finding.to_dict())).hexdigest()


def _artifact_uri(path: str, path_prefix: str) -> str:
    prefixed = (
        PurePosixPath(path_prefix) / PurePosixPath(path)
        if path_prefix
        else PurePosixPath(path)
    )
    return quote(prefixed.as_posix(), safe="/-._~")


def to_sarif(report: ScanReport, *, path_prefix: str = "") -> dict[str, Any]:
    findings = list(report.findings)
    admission_decisions = decision_map(report)
    representative: dict[str, Finding] = {}
    for finding in findings:
        representative.setdefault(finding.rule_id, finding)
    rules = []
    for rule_id in sorted(representative):
        finding = representative[rule_id]
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace(".", "-"),
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
                "properties": {
                    "capability": finding.capability,
                    "defaultSeverity": finding.severity.value,
                },
            }
        )

    results = []
    for finding in findings:
        region = {"startLine": finding.line} if finding.line is not None else {}
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": _artifact_uri(finding.path, path_prefix),
                },
            }
        }
        if region:
            location["physicalLocation"]["region"] = region
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.message},
            "locations": [location],
            "partialFingerprints": {
                "pgextassure/v1": _fingerprint(finding),
            },
            "properties": {
                "severity": finding.severity.value,
                "title": finding.title,
                "evidence": finding.evidence,
                "capability": finding.capability,
                "remediation": finding.remediation,
            },
        }
        if admission_decisions:
            root_cause_id = root_cause_id_for_finding(finding)
            decision = admission_decisions[root_cause_id]
            result["properties"].update(
                {
                    "rootCauseId": root_cause_id,
                    "admissionStatus": decision["status"],
                }
            )
            if decision["status"] == "baselined":
                result["baselineState"] = "unchanged"
            elif decision["status"] == "suppressed":
                result["suppressions"] = [
                    {
                        "kind": "external",
                        "status": "accepted",
                        "justification": (
                            f"{decision['owner']}: {decision['reason']} "
                            f"(expires {decision['expires_on']})"
                        ),
                    }
                ]
        results.append(result)
    run_properties: dict[str, Any] = {
        "manifestDigest": report.manifest.digest,
        "filesScanned": report.summary.files_scanned,
        "coverageDigest": report.coverage.digest,
        "skippedFiles": len(report.coverage.skipped_files),
    }
    if report.scope is not None:
        run_properties.update(
            {
                "scopePlanDigest": report.scope["plan"]["digest"],
                "scopeRoots": report.scope["roots"],
                "scopeExclusions": len(report.scope["exclusions"]),
            }
        )
    if report.generation is not None:
        plan = report.generation["plan"]
        run_properties.update(
            {
                "generationPlanDigest": plan["digest"],
                "generatedArtifacts": len(report.generation["artifacts"]),
            }
        )
    if report.admission is not None:
        admission = report.admission
        run_properties.update(
            {
                "admissionSchemaVersion": admission["schema_version"],
                "admissionSummary": admission["summary"],
            }
        )
        if "baseline" in admission:
            run_properties["baselineDigest"] = admission["baseline"]["digest"]
        if "suppressions" in admission:
            run_properties["suppressionsDigest"] = admission["suppressions"][
                "digest"
            ]
    if report.policy is not None:
        run_properties.update(
            {
                "policyDigest": report.policy["digest"],
                "policyBlockedRootCauses": report.policy["result"][
                    "blocked_count"
                ],
                "policyCoverageViolation": report.policy["result"][
                    "coverage_violation"
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool["name"],
                        "semanticVersion": report.tool["version"],
                        "informationUri": (
                            "https://github.com/borborich/pgextassure"
                        ),
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": run_properties,
            }
        ],
    }


def render_sarif(report: ScanReport, *, path_prefix: str = "") -> str:
    return json.dumps(
        to_sarif(report, path_prefix=path_prefix),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    ) + "\n"


def _workflow_command_value(value: object, *, property_value: bool) -> str:
    """Escape untrusted text for a single GitHub workflow command line."""

    escaped = sanitize_terminal_text(value).replace("%", "%25")
    escaped = escaped.replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        escaped = escaped.replace(":", "%3A").replace(",", "%2C")
    return escaped


def _annotation_path(path: str, path_prefix: str) -> str:
    return (
        (PurePosixPath(path_prefix) / PurePosixPath(path)).as_posix()
        if path_prefix
        else PurePosixPath(path).as_posix()
    )


def render_github_annotations(
    report: ScanReport,
    *,
    mode: str,
    path_prefix: str = "",
    maximum: int = 25,
) -> str:
    """Render bounded, evidence-free GitHub workflow annotations."""

    if mode not in {"active", "all"}:
        raise ValueError("annotation mode must be 'active' or 'all'")
    if not 2 <= maximum <= 50:
        raise ValueError("annotation maximum must be between 2 and 50")

    decisions = decision_map(report)
    commands: list[str] = []
    if (
        report.policy is not None
        and report.policy["result"]["coverage_violation"]
    ):
        policy_result = report.policy["result"]
        commands.append(
            "::error title=PgExtAssure policy coverage::"
            + _workflow_command_value(
                (
                    f"Policy allows at most "
                    f"{report.policy['gate']['maximum_skipped_files']} "
                    f"skipped files, but the scan recorded "
                    f"{policy_result['skipped_count']}."
                ),
                property_value=False,
            )
        )

    for group in group_findings(report.findings):
        decision = decisions.get(group.root_cause_id)
        status = "active" if decision is None else decision["status"]
        if mode == "active" and status not in {"active", "expired"}:
            continue
        if status in {"baselined", "suppressed"}:
            command = "notice"
        elif group.severity in {Severity.CRITICAL, Severity.HIGH}:
            command = "error"
        elif group.severity is Severity.MEDIUM:
            command = "warning"
        else:
            command = "notice"

        location = group.locations[0]
        properties = [
            "file="
            + _workflow_command_value(
                _annotation_path(location.path, path_prefix),
                property_value=True,
            ),
            "title="
            + _workflow_command_value(
                f"PgExtAssure {group.rule_id} [{status}]",
                property_value=True,
            ),
        ]
        if location.line is not None:
            properties.append(f"line={location.line}")
        message = (
            f"{group.title}: {group.message} "
            f"Remediation: {group.remediation}"
        )
        commands.append(
            f"::{command} {','.join(properties)}::"
            + _workflow_command_value(message[:2048], property_value=False)
        )

    if len(commands) > maximum:
        omitted = len(commands) - (maximum - 1)
        commands = commands[: maximum - 1]
        commands.append(
            "::notice title=PgExtAssure annotations truncated::"
            f"{omitted} additional root causes were omitted; "
            "review the complete report artifact."
        )
    return "".join(command + "\n" for command in commands)


def render_text(report: ScanReport) -> str:
    summary = report.summary
    counts = summary.by_severity
    lines = [
        f"PgExtAssure {report.tool['version']}",
        f"Manifest: {report.manifest.digest}",
        (
            f"Coverage: {report.coverage.digest} | "
            f"Skipped: {len(report.coverage.skipped_files)}"
        ),
        (
            f"Files: {summary.files_scanned} | Findings: {summary.findings} "
            f"(critical {counts['critical']}, high {counts['high']}, "
            f"medium {counts['medium']}, low {counts['low']})"
        ),
    ]
    if report.scope is not None:
        lines.insert(
            2,
            (
                f"Scope plan: {report.scope['plan']['digest']} | "
                f"Roots: {len(report.scope['roots'])} | "
                f"Exclusions: {len(report.scope['exclusions'])}"
            ),
        )
    if report.generation is not None:
        lines.insert(
            2,
            (
                "Generation plan: "
                f"{report.generation['plan']['digest']} | "
                f"Virtual artifacts: {len(report.generation['artifacts'])}"
            ),
        )
    admission_decisions = decision_map(report)
    if report.admission is not None:
        admission_summary = report.admission["summary"]
        lines.append(
            "Admission root causes: "
            f"active {admission_summary['active']}, "
            f"baselined {admission_summary['baselined']}, "
            f"suppressed {admission_summary['suppressed']}, "
            f"expired {admission_summary['expired']}"
        )
    if report.policy is not None:
        policy_result = report.policy["result"]
        lines.append(
            "Policy: "
            f"{report.policy['digest']} | "
            f"blocked root causes {policy_result['blocked_count']} | "
            "coverage violation "
            f"{'yes' if policy_result['coverage_violation'] else 'no'}"
        )
    for finding in report.findings:
        location = sanitize_terminal_text(finding.path)
        if finding.line is not None:
            location += f":{finding.line}"
        status = ""
        decision: dict[str, Any] | None = None
        if admission_decisions:
            decision = admission_decisions[
                root_cause_id_for_finding(finding)
            ]
            status = f" [{decision['status'].upper()}]"
        lines.extend(
            [
                "",
                (
                    f"{finding.severity.value.upper()}{status} "
                    f"{sanitize_terminal_text(finding.rule_id)} {location}"
                ),
                f"  {sanitize_terminal_text(finding.title)}",
                f"  {sanitize_terminal_text(finding.message)}",
                f"  Evidence: {sanitize_terminal_text(finding.evidence)}",
                f"  Capability: {sanitize_terminal_text(finding.capability)}",
                f"  Remediation: {sanitize_terminal_text(finding.remediation)}",
            ]
        )
        if decision is not None and decision["status"] in {
            "suppressed",
            "expired",
        }:
            lines.append(
                "  Admission: "
                f"owner {sanitize_terminal_text(decision['owner'])}; "
                f"expires {decision['expires_on']}; "
                f"reason {sanitize_terminal_text(decision['reason'])}"
            )
    return "\n".join(lines) + "\n"
