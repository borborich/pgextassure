"""Conservative, deterministic grouping of findings by reviewable root cause."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
from typing import Any, Iterable

from .models import Finding, SEVERITY_RANK, ScanReport, Severity
from .source import canonical_json_bytes


GROUPING_STRATEGY = "conservative-v1"
_ROUTINE_IDENTITY_PREFIX = "routine = "
_SEMANTIC_ROUTINE_RULES = frozenset(
    {
        "sql.security-definer-public-execute",
        "sql.security-definer-search-path",
    }
)
_GENERIC_SQL_DIRECTORIES = frozenset(
    {"migration", "migrations", "sql", "update", "updates", "upgrade", "upgrades"}
)


@dataclass(frozen=True, slots=True)
class FindingLocation:
    """One source location represented by a grouped finding."""

    path: str
    line: int | None

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line}

    def sort_key(self) -> tuple[str, int]:
        return (self.path, self.line or 0)


@dataclass(frozen=True, slots=True)
class RootCauseGroup:
    """A set of findings proven to describe the same reviewable cause."""

    root_cause_id: str
    rule_id: str
    severity: Severity
    title: str
    message: str
    identity: str
    scope: str
    capability: str
    remediation: str
    locations: tuple[FindingLocation, ...]

    @property
    def occurrence_count(self) -> int:
        return len(self.locations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_cause_id": self.root_cause_id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "identity": self.identity,
            "scope": self.scope,
            "capability": self.capability,
            "remediation": self.remediation,
            "occurrence_count": self.occurrence_count,
            "locations": [location.to_dict() for location in self.locations],
        }

    def sort_key(self) -> tuple[int, str, str, str]:
        return (
            -SEVERITY_RANK[self.severity],
            self.rule_id,
            self.scope,
            self.identity,
        )


def _sql_artifact_scope(path: str) -> str:
    """Identify an extension artifact family without depending on its version."""

    artifact = PurePosixPath(path)
    name = artifact.name
    lowered = name.casefold()
    if lowered.endswith(".sql.in"):
        stem = name[:-7]
    elif lowered.endswith(".sql"):
        stem = name[:-4]
    else:
        return artifact.parent.as_posix()

    extension_name = stem.split("--", 1)[0]
    parents = list(artifact.parent.parts)
    while parents and parents[-1].casefold() in _GENERIC_SQL_DIRECTORIES:
        parents.pop()
    scope = PurePosixPath(*parents, extension_name).as_posix()
    return scope or extension_name


def _semantic_identity(finding: Finding) -> tuple[str, str] | None:
    if (
        finding.rule_id in _SEMANTIC_ROUTINE_RULES
        and finding.evidence.startswith(_ROUTINE_IDENTITY_PREFIX)
    ):
        return (_sql_artifact_scope(finding.path), finding.evidence)
    return None


def _group_discriminator(finding: Finding) -> tuple[object, ...]:
    semantic = _semantic_identity(finding)
    common = (
        finding.rule_id,
        finding.severity.value,
        finding.capability,
    )
    if semantic is not None:
        scope, identity = semantic
        return ("semantic", *common, scope, identity)
    return (
        "location",
        *common,
        finding.path,
        finding.line,
        finding.message,
        finding.evidence,
    )


def _root_cause_id(discriminator: tuple[object, ...]) -> str:
    payload = {
        "namespace": "pgextassure.root-cause/v1",
        "discriminator": list(discriminator),
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def root_cause_id_for_finding(finding: Finding) -> str:
    """Return the stable root-cause identifier used by grouped reports."""

    return _root_cause_id(_group_discriminator(finding))


def group_findings(findings: Iterable[Finding]) -> tuple[RootCauseGroup, ...]:
    """Group only findings with an explicit, rule-specific semantic identity."""

    grouped: dict[tuple[object, ...], list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(_group_discriminator(finding), []).append(finding)

    results: list[RootCauseGroup] = []
    for discriminator, occurrences in grouped.items():
        ordered = sorted(occurrences, key=Finding.sort_key)
        representative = ordered[0]
        semantic = _semantic_identity(representative)
        if semantic is None:
            scope = PurePosixPath(representative.path).parent.as_posix()
            identity = representative.evidence
        else:
            scope, identity = semantic
        locations = tuple(
            sorted(
                (
                    FindingLocation(path=finding.path, line=finding.line)
                    for finding in ordered
                ),
                key=FindingLocation.sort_key,
            )
        )
        results.append(
            RootCauseGroup(
                root_cause_id=_root_cause_id(discriminator),
                rule_id=representative.rule_id,
                severity=representative.severity,
                title=representative.title,
                message=representative.message,
                identity=identity,
                scope=scope,
                capability=representative.capability,
                remediation=representative.remediation,
                locations=locations,
            )
        )
    return tuple(sorted(results, key=RootCauseGroup.sort_key))


def grouped_report_document(report: ScanReport) -> dict[str, Any]:
    """Return a JSON-compatible grouped report without changing report v1."""

    groups = group_findings(report.findings)
    root_cause_counts = Counter(group.severity.value for group in groups)
    root_causes = [group.to_dict() for group in groups]
    if report.admission is not None:
        decisions = {
            decision["root_cause_id"]: decision
            for decision in report.admission["decisions"]
        }
        for root_cause in root_causes:
            decision = decisions[root_cause["root_cause_id"]]
            root_cause["admission"] = {
                key: value
                for key, value in decision.items()
                if key not in {"root_cause_id", "rule_id", "severity"}
            }
    document = {
        "schema_version": "1.2",
        "report_type": "pgextassure.root-cause-groups",
        "tool": dict(report.tool),
        "manifest": report.manifest.to_dict(),
        "coverage": report.coverage.to_dict(),
        "grouping": {
            "strategy": GROUPING_STRATEGY,
            "semantic_rules": sorted(_SEMANTIC_ROUTINE_RULES),
        },
        "summary": {
            "files_scanned": report.summary.files_scanned,
            "findings": report.summary.findings,
            "root_causes": len(groups),
            "findings_by_severity": dict(report.summary.by_severity),
            "root_causes_by_severity": {
                severity.value: root_cause_counts[severity.value]
                for severity in Severity
            },
            "capabilities": list(report.summary.capabilities),
        },
        "root_causes": root_causes,
    }
    if report.generation is not None:
        document["generation"] = report.generation
        document["source_report_schema_version"] = report.schema_version
    if report.admission is not None:
        document["admission"] = report.admission
        document["source_report_schema_version"] = report.schema_version
    if report.policy is not None:
        document["policy"] = report.policy
        document["source_report_schema_version"] = report.schema_version
    return document
