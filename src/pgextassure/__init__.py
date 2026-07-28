"""PgExtAssure's public Python API."""

from .grouping import (
    FindingLocation,
    RootCauseGroup,
    group_findings,
    grouped_report_document,
)
from .models import Finding, ScanManifest, ScanReport, Severity
from .scanner import ScanError, scan_path
from ._version import PACKAGE_VERSION, RELEASE_VERSION

__all__ = [
    "Finding",
    "FindingLocation",
    "RootCauseGroup",
    "ScanError",
    "ScanManifest",
    "ScanReport",
    "Severity",
    "group_findings",
    "grouped_report_document",
    "scan_path",
]

__version__ = PACKAGE_VERSION
__release_version__ = RELEASE_VERSION
