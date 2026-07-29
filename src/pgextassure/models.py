"""Stable, JSON-compatible models used by the scanner and reporters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable


class Severity(str, Enum):
    """Finding severities, ordered from most to least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


@dataclass(frozen=True, slots=True)
class Finding:
    """A single static-analysis result.

    Every field is deliberately serializable without custom encoders. ``line`` is
    one-based when known and ``None`` for a file-level result.
    """

    rule_id: str
    severity: Severity
    title: str
    message: str
    path: str
    line: int | None
    evidence: str
    capability: str
    remediation: str

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("finding rule_id must not be empty")
        if self.line is not None and self.line < 1:
            raise ValueError("finding line must be one-based")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "capability": self.capability,
            "remediation": self.remediation,
        }

    def sort_key(self) -> tuple[int, str, int, str, str]:
        return (
            -SEVERITY_RANK[self.severity],
            self.path,
            self.line or 0,
            self.rule_id,
            self.message,
        )


@dataclass(frozen=True, slots=True)
class ManifestFile:
    path: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class ScanManifest:
    algorithm: str
    digest: str
    files: tuple[ManifestFile, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "digest": self.digest,
            "files": [item.to_dict() for item in self.files],
        }


@dataclass(frozen=True, slots=True)
class ScanSummary:
    files_scanned: int
    findings: int
    by_severity: dict[str, int]
    capabilities: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "findings": self.findings,
            "by_severity": dict(self.by_severity),
            "capabilities": list(self.capabilities),
        }


@dataclass(frozen=True, slots=True)
class ScanReport:
    schema_version: str
    tool: dict[str, str]
    manifest: ScanManifest
    summary: ScanSummary
    findings: tuple[Finding, ...]
    generation: dict[str, Any] | None = None
    admission: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        document = {
            "schema_version": self.schema_version,
            "tool": dict(self.tool),
            "manifest": self.manifest.to_dict(),
            "summary": self.summary.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
        if self.generation is not None:
            document["generation"] = self.generation
        if self.admission is not None:
            document["admission"] = self.admission
        return document


def build_summary(
    files_scanned: int, findings: Iterable[Finding]
) -> ScanSummary:
    materialized = tuple(findings)
    counts = {severity.value: 0 for severity in Severity}
    for finding in materialized:
        counts[finding.severity.value] += 1
    return ScanSummary(
        files_scanned=files_scanned,
        findings=len(materialized),
        by_severity=counts,
        capabilities=tuple(
            sorted({finding.capability for finding in materialized})
        ),
    )
