"""PgExtAssure's public Python API."""

from .admission import (
    AdmissionError,
    Baseline,
    Suppression,
    SuppressionSet,
    apply_admission,
    create_baseline_document,
    load_baseline,
    load_suppressions,
)
from .grouping import (
    FindingLocation,
    RootCauseGroup,
    group_findings,
    grouped_report_document,
)
from .generation import (
    GeneratedArtifact,
    GenerationInput,
    GenerationPlan,
    GenerationPlanError,
    load_generation_plan,
)
from .evidence import (
    BUNDLE_SCHEMA_VERSION,
    EVIDENCE_PREDICATE_TYPE,
    EvidenceError,
    EvidenceVerification,
    build_spdx_inventory,
    create_evidence_bundle,
    verify_evidence_bundle,
)
from .models import Finding, ScanManifest, ScanReport, Severity
from .scanner import ScanError, scan_path
from .scope import (
    ScopeExclusion,
    ScopePlan,
    ScopePlanError,
    load_scope_plan,
    parse_scope_plan,
)
from ._version import PACKAGE_VERSION, RELEASE_VERSION

__all__ = [
    "AdmissionError",
    "Baseline",
    "BUNDLE_SCHEMA_VERSION",
    "EVIDENCE_PREDICATE_TYPE",
    "EvidenceError",
    "EvidenceVerification",
    "Finding",
    "FindingLocation",
    "GeneratedArtifact",
    "GenerationInput",
    "GenerationPlan",
    "GenerationPlanError",
    "RootCauseGroup",
    "ScanError",
    "ScanManifest",
    "ScanReport",
    "ScopeExclusion",
    "ScopePlan",
    "ScopePlanError",
    "Severity",
    "Suppression",
    "SuppressionSet",
    "apply_admission",
    "build_spdx_inventory",
    "create_evidence_bundle",
    "create_baseline_document",
    "group_findings",
    "grouped_report_document",
    "load_generation_plan",
    "load_baseline",
    "load_suppressions",
    "load_scope_plan",
    "parse_scope_plan",
    "scan_path",
    "verify_evidence_bundle",
]

__version__ = PACKAGE_VERSION
__release_version__ = RELEASE_VERSION
