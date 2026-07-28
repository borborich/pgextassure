"""Deterministic text, JSON, and SARIF 2.1 reporters."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from .grouping import grouped_report_document
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
        results.append(
            {
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
        )
    run_properties: dict[str, Any] = {
        "manifestDigest": report.manifest.digest,
        "filesScanned": report.summary.files_scanned,
    }
    if report.generation is not None:
        plan = report.generation["plan"]
        run_properties.update(
            {
                "generationPlanDigest": plan["digest"],
                "generatedArtifacts": len(report.generation["artifacts"]),
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


def render_text(report: ScanReport) -> str:
    summary = report.summary
    counts = summary.by_severity
    lines = [
        f"PgExtAssure {report.tool['version']}",
        f"Manifest: {report.manifest.digest}",
        (
            f"Files: {summary.files_scanned} | Findings: {summary.findings} "
            f"(critical {counts['critical']}, high {counts['high']}, "
            f"medium {counts['medium']}, low {counts['low']})"
        ),
    ]
    if report.generation is not None:
        lines.insert(
            2,
            (
                "Generation plan: "
                f"{report.generation['plan']['digest']} | "
                f"Virtual artifacts: {len(report.generation['artifacts'])}"
            ),
        )
    for finding in report.findings:
        location = sanitize_terminal_text(finding.path)
        if finding.line is not None:
            location += f":{finding.line}"
        lines.extend(
            [
                "",
                (
                    f"{finding.severity.value.upper()} "
                    f"{sanitize_terminal_text(finding.rule_id)} {location}"
                ),
                f"  {sanitize_terminal_text(finding.title)}",
                f"  {sanitize_terminal_text(finding.message)}",
                f"  Evidence: {sanitize_terminal_text(finding.evidence)}",
                f"  Capability: {sanitize_terminal_text(finding.capability)}",
                f"  Remediation: {sanitize_terminal_text(finding.remediation)}",
            ]
        )
    return "\n".join(lines) + "\n"
