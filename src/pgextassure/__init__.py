"""PgExtAssure's public Python API."""

from .models import Finding, ScanManifest, ScanReport, Severity
from .scanner import ScanError, scan_path
from ._version import PACKAGE_VERSION, RELEASE_VERSION

__all__ = [
    "Finding",
    "ScanError",
    "ScanManifest",
    "ScanReport",
    "Severity",
    "scan_path",
]

__version__ = PACKAGE_VERSION
__release_version__ = RELEASE_VERSION
