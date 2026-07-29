"""Deterministic, bounded evidence bundles for independent admission review."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping
import zipfile

from .models import ScanReport
from .source import canonical_json_bytes
from .scope import ScopePlanError, parse_scope_plan


BUNDLE_SCHEMA_VERSION = "1.0"
BUNDLE_TYPE = "pgextassure.evidence"
EVIDENCE_PREDICATE_TYPE = (
    "https://github.com/borborich/pgextassure/attestation/evidence/v1"
)
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_MATERIAL_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_ENTRIES = 8
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_MATERIAL_NAMES = {
    "baseline": "inputs/baseline.json",
    "generation_plan": "inputs/generation-plan.json",
    "policy": "inputs/policy.json",
    "scope_plan": "inputs/scope-plan.json",
    "suppressions": "inputs/suppressions.json",
}


class EvidenceError(ValueError):
    """An evidence bundle is unsafe, malformed, or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class EvidenceVerification:
    """Verified evidence metadata suitable for CLI rendering."""

    predicate: dict[str, Any]
    sbom: dict[str, Any]
    summary: dict[str, Any]


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise EvidenceError(f"duplicate JSON key {key!r}")
        document[key] = value
    return document


def _load_json(raw: bytes, *, label: str) -> Any:
    if b"\x00" in raw:
        raise EvidenceError(f"{label} contains binary data")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{label} is not UTF-8") from error
    try:
        return json.loads(text, object_pairs_hook=_pairs_object)
    except EvidenceError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise EvidenceError(f"{label} is not valid JSON: {error}") from error


def _plain_object(
    value: object,
    *,
    label: str,
    fields: frozenset[str],
    required: frozenset[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    unknown = set(value) - fields
    if unknown:
        raise EvidenceError(
            f"{label} contains unknown fields: {', '.join(sorted(unknown))}"
        )
    missing = (required or fields) - set(value)
    if missing:
        raise EvidenceError(
            f"{label} is missing fields: {', '.join(sorted(missing))}"
        )
    return value


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_component_value(
    value: str | None,
    *,
    label: str,
    required: bool,
) -> str | None:
    if value is None and not required:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8", errors="surrogatepass")) > 256
        or any(
            ord(character) < 0x20
            or 0x7F <= ord(character) <= 0x9F
            or 0xD800 <= ord(character) <= 0xDFFF
            or ord(character)
            in {
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
            for character in value
        )
        or "\x7f" in value
    ):
        raise EvidenceError(f"{label} must be printable UTF-8 up to 256 bytes")
    return value


def _spdx_file_id(index: int, path: str) -> str:
    fingerprint = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    return f"SPDXRef-File-{index:05d}-{fingerprint}"


def build_spdx_inventory(
    report: ScanReport,
    *,
    created_on: date,
    component_name: str,
    component_version: str | None,
) -> dict[str, Any]:
    """Build an honest SPDX 2.3 inventory of analyzed source files."""

    name = _validate_component_value(
        component_name,
        label="component name",
        required=True,
    )
    version = _validate_component_value(
        component_version,
        label="component version",
        required=False,
    )
    namespace_seed = {
        "component_name": name,
        "component_version": version,
        "created_on": created_on.isoformat(),
        "manifest_digest": report.manifest.digest,
    }
    namespace_digest = hashlib.sha256(
        canonical_json_bytes(namespace_seed)
    ).hexdigest()
    package: dict[str, Any] = {
        "SPDXID": "SPDXRef-Package",
        "name": name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "SOURCE",
        "comment": (
            "Inventory is limited to files analyzed by PgExtAssure. "
            "Skipped files, generated outputs, build tools, and transitive "
            "dependencies are not resolved and are described in report.json."
        ),
    }
    if version is not None:
        package["versionInfo"] = version

    files: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package",
        }
    ]
    for index, item in enumerate(report.manifest.files, start=1):
        spdx_id = _spdx_file_id(index, item.path)
        files.append(
            {
                "SPDXID": spdx_id,
                "fileName": "./" + item.path,
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": item.sha256,
                    }
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spdx_id,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name} PgExtAssure analyzed-source inventory",
        "documentNamespace": (
            "https://github.com/borborich/pgextassure/evidence/spdx/"
            + namespace_digest
        ),
        "creationInfo": {
            "created": created_on.isoformat() + "T00:00:00Z",
            "creators": [
                (
                    "Tool: pgextassure-"
                    + report.tool["version"]
                )
            ],
            "comment": (
                "This SPDX document is a bounded analyzed-source inventory, "
                "not a complete dependency-resolution claim."
            ),
        },
        "packages": [package],
        "files": files,
        "relationships": relationships,
    }


def expected_material_digests(report: ScanReport) -> dict[str, str]:
    """Return exact configuration-file digests retained by the report."""

    expected: dict[str, str] = {}
    if report.scope is not None:
        expected["scope_plan"] = report.scope["plan"]["digest"]
    if report.generation is not None:
        expected["generation_plan"] = report.generation["plan"]["digest"]
    if report.admission is not None:
        if "baseline" in report.admission:
            expected["baseline"] = report.admission["baseline"]["digest"]
        if "suppressions" in report.admission:
            expected["suppressions"] = report.admission["suppressions"]["digest"]
    if report.policy is not None:
        expected["policy"] = report.policy["digest"]
    return expected


def read_evidence_material(
    path: str | os.PathLike[str],
    *,
    expected_digest: str,
) -> bytes:
    """Read one already-validated control input without following symlinks."""

    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise EvidenceError(
            f"cannot inspect evidence input {candidate}: {error}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode):
        raise EvidenceError(f"evidence input must not be a symlink: {candidate}")
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(
            f"evidence input must be a regular file: {candidate}"
        )
    if metadata.st_size > MAX_MATERIAL_BYTES:
        raise EvidenceError(
            f"evidence input exceeds {MAX_MATERIAL_BYTES} bytes: {candidate}"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise EvidenceError(
                f"evidence input changed type while opening: {candidate}"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(MAX_MATERIAL_BYTES + 1)
    except EvidenceError:
        raise
    except OSError as error:
        raise EvidenceError(
            f"cannot read evidence input {candidate}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_MATERIAL_BYTES:
        raise EvidenceError(
            f"evidence input exceeds {MAX_MATERIAL_BYTES} bytes: {candidate}"
        )
    if _digest_bytes(raw) != expected_digest:
        raise EvidenceError(
            f"evidence input changed after validation: {candidate}"
        )
    return raw


def _zip_bytes(files: Mapping[str, bytes]) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name])
    rendered = output.getvalue()
    if len(rendered) > MAX_BUNDLE_BYTES:
        raise EvidenceError(
            f"evidence bundle exceeds {MAX_BUNDLE_BYTES} bytes"
        )
    return rendered


def create_evidence_bundle(
    report: ScanReport,
    *,
    created_on: date,
    component_name: str,
    component_version: str | None,
    blocked: bool,
    fail_on: str,
    materials: Mapping[str, bytes],
) -> bytes:
    """Create one deterministic evidence bundle without source-tree contents."""

    if fail_on not in {"none", "low", "medium", "high", "critical"}:
        raise EvidenceError("fail_on is invalid")
    if report.policy is not None and fail_on != "none":
        raise EvidenceError("policy-controlled evidence must use fail_on none")
    expected = expected_material_digests(report)
    if set(materials) != set(expected):
        raise EvidenceError(
            "evidence materials do not match the controls retained by the report"
        )
    payloads: dict[str, bytes] = {
        "report.json": _json_bytes(report.to_dict()),
        "sbom.spdx.json": _json_bytes(
            build_spdx_inventory(
                report,
                created_on=created_on,
                component_name=component_name,
                component_version=component_version,
            )
        ),
    }
    media_types = {
        "report.json": "application/vnd.pgextassure.scan-report+json",
        "sbom.spdx.json": "application/spdx+json",
    }
    for material, raw in materials.items():
        if _digest_bytes(raw) != expected[material]:
            raise EvidenceError(
                f"{material} bytes do not match the report digest"
            )
        name = _MATERIAL_NAMES[material]
        payloads[name] = raw
        media_types[name] = "application/json"

    file_index = [
        {
            "name": name,
            "media_type": media_types[name],
            "size": len(payloads[name]),
            "digest": _digest_bytes(payloads[name]),
        }
        for name in sorted(payloads)
    ]
    predicate = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_type": BUNDLE_TYPE,
        "predicate_type": EVIDENCE_PREDICATE_TYPE,
        "created_on": created_on.isoformat(),
        "subject": {
            "manifest_digest": report.manifest.digest,
            "coverage_digest": report.coverage.digest,
            "component": {
                "name": component_name,
                "version": component_version,
            },
        },
        "tool": dict(report.tool),
        "result": {
            "fail_on": fail_on,
            "gate": "blocked" if blocked else "pass",
            "policy_digest": (
                report.policy["digest"] if report.policy is not None else None
            ),
        },
        "privacy": {
            "source_files_included": False,
            "report_contains_matched_evidence": True,
        },
        "sbom": {
            "format": "SPDX-2.3",
            "scope": "analyzed-source-inventory",
            "dependency_resolution": "not-performed",
        },
        "files": file_index,
    }
    all_files = {"bundle.json": _json_bytes(predicate), **payloads}
    return _zip_bytes(all_files)


def _read_bundle(path: str | os.PathLike[str]) -> dict[str, bytes]:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise EvidenceError(f"cannot inspect evidence bundle: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise EvidenceError("evidence bundle must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError("evidence bundle must be a regular file")
    if metadata.st_size > MAX_BUNDLE_BYTES:
        raise EvidenceError(
            f"evidence bundle exceeds {MAX_BUNDLE_BYTES} bytes"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise EvidenceError("evidence bundle changed type while opening")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            try:
                archive = zipfile.ZipFile(handle)
            except (OSError, zipfile.BadZipFile) as error:
                raise EvidenceError(
                    f"evidence bundle is not a valid ZIP: {error}"
                ) from error
            with archive:
                infos = archive.infolist()
                if not 1 <= len(infos) <= MAX_BUNDLE_ENTRIES:
                    raise EvidenceError(
                        "evidence bundle entry count is outside the allowed range"
                    )
                names = [info.filename for info in infos]
                if len(names) != len(set(names)):
                    raise EvidenceError("evidence bundle contains duplicate entries")
                files: dict[str, bytes] = {}
                total = 0
                for info in infos:
                    path = PurePosixPath(info.filename)
                    if (
                        path.is_absolute()
                        or not path.parts
                        or ".." in path.parts
                        or "\\" in info.filename
                        or info.is_dir()
                    ):
                        raise EvidenceError(
                            f"unsafe evidence bundle entry: {info.filename!r}"
                        )
                    if info.flag_bits & 0x1:
                        raise EvidenceError(
                            "encrypted evidence bundle entries are not allowed"
                        )
                    if info.create_system == 3 and stat.S_ISLNK(
                        info.external_attr >> 16
                    ):
                        raise EvidenceError(
                            "symlink evidence bundle entries are not allowed"
                        )
                    if info.compress_type not in {
                        zipfile.ZIP_STORED,
                        zipfile.ZIP_DEFLATED,
                    }:
                        raise EvidenceError(
                            f"unsupported compression for {info.filename!r}"
                        )
                    if info.file_size > MAX_ENTRY_BYTES:
                        raise EvidenceError(
                            f"evidence entry exceeds {MAX_ENTRY_BYTES} bytes"
                        )
                    total += info.file_size
                    if total > MAX_BUNDLE_BYTES:
                        raise EvidenceError(
                            "evidence bundle expands beyond the total size limit"
                        )
                    with archive.open(info, "r") as entry:
                        raw = entry.read(MAX_ENTRY_BYTES + 1)
                    if len(raw) != info.file_size:
                        raise EvidenceError(
                            f"evidence entry size mismatch: {info.filename!r}"
                        )
                    files[info.filename] = raw
                if names != sorted(names):
                    raise EvidenceError(
                        "evidence bundle entries are not deterministically ordered"
                    )
                return files
    except EvidenceError:
        raise
    except (
        EOFError,
        NotImplementedError,
        OSError,
        RuntimeError,
        zipfile.BadZipFile,
    ) as error:
        raise EvidenceError(f"cannot read evidence bundle: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise EvidenceError(f"{label} is not a SHA-256 digest")
    return value


def _verify_manifest_and_coverage(report: dict[str, Any]) -> None:
    manifest = _plain_object(
        report.get("manifest"),
        label="report manifest",
        fields=frozenset({"algorithm", "digest", "files"}),
    )
    if manifest["algorithm"] != "sha256" or not isinstance(
        manifest["files"], list
    ):
        raise EvidenceError("report manifest contract is invalid")
    manifest_payload: list[dict[str, Any]] = []
    previous_path: str | None = None
    for item in manifest["files"]:
        entry = _plain_object(
            item,
            label="manifest file",
            fields=frozenset({"path", "size", "sha256"}),
        )
        path = entry["path"]
        if (
            not isinstance(path, str)
            or not path
            or (previous_path is not None and path <= previous_path)
            or type(entry["size"]) is not int
            or entry["size"] < 0
            or not isinstance(entry["sha256"], str)
            or not _HEX_DIGEST_PATTERN.fullmatch(entry["sha256"])
        ):
            raise EvidenceError("report manifest file contract is invalid")
        previous_path = path
        manifest_payload.append(entry)
    expected_manifest = "sha256:" + hashlib.sha256(
        canonical_json_bytes(manifest_payload)
    ).hexdigest()
    if manifest["digest"] != expected_manifest:
        raise EvidenceError("report manifest digest does not verify")

    coverage = _plain_object(
        report.get("coverage"),
        label="report coverage",
        fields=frozenset(
            {
                "algorithm",
                "digest",
                "analyzed_files",
                "skipped_count",
                "skipped_files",
            }
        ),
    )
    if (
        coverage["algorithm"] != "sha256"
        or coverage["analyzed_files"] != len(manifest_payload)
        or type(coverage["skipped_count"]) is not int
        or not isinstance(coverage["skipped_files"], list)
        or coverage["skipped_count"] != len(coverage["skipped_files"])
    ):
        raise EvidenceError("report coverage contract is invalid")
    coverage_payload = {
        "analyzed_files": coverage["analyzed_files"],
        "skipped_files": coverage["skipped_files"],
    }
    expected_coverage = "sha256:" + hashlib.sha256(
        canonical_json_bytes(coverage_payload)
    ).hexdigest()
    if coverage["digest"] != expected_coverage:
        raise EvidenceError("report coverage digest does not verify")


def _verify_findings_and_summary(report: dict[str, Any]) -> None:
    findings = report["findings"]
    if not isinstance(findings, list):
        raise EvidenceError("report findings are invalid")
    severities = ("critical", "high", "medium", "low")
    counts = {severity: 0 for severity in severities}
    capabilities: set[str] = set()
    finding_fields = {
        "rule_id",
        "severity",
        "title",
        "message",
        "path",
        "line",
        "evidence",
        "capability",
        "remediation",
    }
    for value in findings:
        finding = _plain_object(
            value,
            label="report finding",
            fields=frozenset(finding_fields),
        )
        severity = finding["severity"]
        capability = finding["capability"]
        if severity not in counts or not isinstance(capability, str) or not capability:
            raise EvidenceError("report finding contract is invalid")
        counts[severity] += 1
        capabilities.add(capability)

    summary = _plain_object(
        report["summary"],
        label="report summary",
        fields=frozenset(
            {"files_scanned", "findings", "by_severity", "capabilities"}
        ),
    )
    if (
        summary["files_scanned"] != report["coverage"]["analyzed_files"]
        or summary["findings"] != len(findings)
        or summary["by_severity"] != counts
        or summary["capabilities"] != sorted(capabilities)
    ):
        raise EvidenceError("report summary does not match the findings")


def _verify_evidence_bundle(
    path: str | os.PathLike[str],
) -> EvidenceVerification:
    """Verify a bundle offline without extracting any archive entry."""

    files = _read_bundle(path)
    if "bundle.json" not in files:
        raise EvidenceError("evidence bundle is missing bundle.json")
    predicate = _plain_object(
        _load_json(files["bundle.json"], label="bundle.json"),
        label="bundle",
        fields=frozenset(
            {
                "schema_version",
                "bundle_type",
                "predicate_type",
                "created_on",
                "subject",
                "tool",
                "result",
                "privacy",
                "sbom",
                "files",
            }
        ),
    )
    if (
        predicate["schema_version"] != BUNDLE_SCHEMA_VERSION
        or predicate["bundle_type"] != BUNDLE_TYPE
        or predicate["predicate_type"] != EVIDENCE_PREDICATE_TYPE
    ):
        raise EvidenceError("unsupported evidence bundle contract")
    try:
        created_on = date.fromisoformat(predicate["created_on"])
    except (TypeError, ValueError) as error:
        raise EvidenceError("bundle created_on is not an ISO date") from error

    subject = _plain_object(
        predicate["subject"],
        label="bundle subject",
        fields=frozenset(
            {"manifest_digest", "coverage_digest", "component"}
        ),
    )
    _validate_digest(
        subject["manifest_digest"],
        label="bundle subject manifest_digest",
    )
    _validate_digest(
        subject["coverage_digest"],
        label="bundle subject coverage_digest",
    )
    component = _plain_object(
        subject["component"],
        label="bundle component",
        fields=frozenset({"name", "version"}),
    )
    _validate_component_value(
        component["name"],
        label="component name",
        required=True,
    )
    _validate_component_value(
        component["version"],
        label="component version",
        required=False,
    )

    tool = _plain_object(
        predicate["tool"],
        label="bundle tool",
        fields=frozenset({"name", "version", "ruleset_version"}),
    )
    if (
        tool["name"] != "pgextassure"
        or not isinstance(tool["version"], str)
        or not tool["version"]
        or not isinstance(tool["ruleset_version"], str)
        or not tool["ruleset_version"]
    ):
        raise EvidenceError("bundle tool contract is invalid")
    result = _plain_object(
        predicate["result"],
        label="bundle result",
        fields=frozenset({"fail_on", "gate", "policy_digest"}),
    )
    fail_on = result["fail_on"]
    severity_rank = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }
    if fail_on not in {"none", *severity_rank}:
        raise EvidenceError("bundle fail_on result is invalid")
    if result["gate"] not in {"pass", "blocked"}:
        raise EvidenceError("bundle gate result is invalid")
    if result["policy_digest"] is not None:
        _validate_digest(
            result["policy_digest"],
            label="bundle policy digest",
        )
    privacy = _plain_object(
        predicate["privacy"],
        label="bundle privacy",
        fields=frozenset(
            {"source_files_included", "report_contains_matched_evidence"}
        ),
    )
    if (
        privacy["source_files_included"] is not False
        or privacy["report_contains_matched_evidence"] is not True
    ):
        raise EvidenceError("unsupported bundle privacy declaration")
    sbom_metadata = _plain_object(
        predicate["sbom"],
        label="bundle sbom",
        fields=frozenset(
            {"format", "scope", "dependency_resolution"}
        ),
    )
    if sbom_metadata != {
        "format": "SPDX-2.3",
        "scope": "analyzed-source-inventory",
        "dependency_resolution": "not-performed",
    }:
        raise EvidenceError("unsupported bundle SBOM declaration")

    index = predicate["files"]
    if not isinstance(index, list) or not 2 <= len(index) < MAX_BUNDLE_ENTRIES:
        raise EvidenceError("bundle file index has an invalid size")
    allowed_media_types = {
        **{
            material_name: "application/json"
            for material_name in _MATERIAL_NAMES.values()
        },
        "report.json": "application/vnd.pgextassure.scan-report+json",
        "sbom.spdx.json": "application/spdx+json",
    }
    indexed_names: list[str] = []
    for value in index:
        item = _plain_object(
            value,
            label="bundle file index entry",
            fields=frozenset({"name", "media_type", "size", "digest"}),
        )
        name = item["name"]
        if (
            not isinstance(name, str)
            or name == "bundle.json"
            or name not in allowed_media_types
            or name not in files
            or type(item["size"]) is not int
            or item["size"] < 0
            or item["media_type"] != allowed_media_types[name]
        ):
            raise EvidenceError("bundle file index entry is invalid")
        _validate_digest(item["digest"], label=f"{name} digest")
        if item["size"] != len(files[name]):
            raise EvidenceError(f"{name} size does not match the index")
        if item["digest"] != _digest_bytes(files[name]):
            raise EvidenceError(f"{name} digest does not match the index")
        indexed_names.append(name)
    if indexed_names != sorted(indexed_names) or len(indexed_names) != len(
        set(indexed_names)
    ):
        raise EvidenceError("bundle file index is not unique and ordered")
    if set(files) != {"bundle.json", *indexed_names}:
        raise EvidenceError("bundle contains an unindexed entry")
    required_payloads = {"report.json", "sbom.spdx.json"}
    if not required_payloads.issubset(files):
        raise EvidenceError("bundle is missing a required payload")

    report = _plain_object(
        _load_json(files["report.json"], label="report.json"),
        label="report",
        fields=frozenset(
            {
                "schema_version",
                "tool",
                "manifest",
                "coverage",
                "summary",
                "findings",
                "scope",
                "generation",
                "admission",
                "policy",
            }
        ),
        required=frozenset(
            {
                "schema_version",
                "tool",
                "manifest",
                "coverage",
                "summary",
                "findings",
            }
        ),
    )
    if report["schema_version"] != "1.4" or report["tool"] != tool:
        raise EvidenceError("bundle report version/tool does not match")
    _verify_manifest_and_coverage(report)
    _verify_findings_and_summary(report)
    if report["manifest"]["digest"] != subject["manifest_digest"]:
        raise EvidenceError("bundle subject manifest does not match the report")
    if report["coverage"]["digest"] != subject["coverage_digest"]:
        raise EvidenceError("bundle subject coverage does not match the report")

    expected_inputs: dict[str, str] = {}
    if "scope" in report:
        expected_inputs["inputs/scope-plan.json"] = report["scope"]["plan"][
            "digest"
        ]
    if "generation" in report:
        expected_inputs["inputs/generation-plan.json"] = report["generation"][
            "plan"
        ]["digest"]
    if "admission" in report:
        if "baseline" in report["admission"]:
            expected_inputs["inputs/baseline.json"] = report["admission"][
                "baseline"
            ]["digest"]
        if "suppressions" in report["admission"]:
            expected_inputs["inputs/suppressions.json"] = report["admission"][
                "suppressions"
            ]["digest"]
    if "policy" in report:
        expected_inputs["inputs/policy.json"] = report["policy"]["digest"]
        if result["policy_digest"] != report["policy"]["digest"]:
            raise EvidenceError("bundle policy result does not match the report")
        if fail_on != "none":
            raise EvidenceError(
                "policy-controlled evidence must record fail_on as none"
            )
        policy_result = report["policy"].get("result")
        if not isinstance(policy_result, dict) or type(
            policy_result.get("blocked")
        ) is not bool:
            raise EvidenceError("report policy result is invalid")
        expected_gate = (
            "blocked" if policy_result["blocked"] else "pass"
        )
    elif result["policy_digest"] is not None:
        raise EvidenceError("bundle declares a policy absent from the report")
    elif fail_on == "none":
        expected_gate = "pass"
    else:
        threshold = severity_rank[fail_on]
        admission = report.get("admission")
        if admission is not None:
            if not isinstance(admission, dict) or not isinstance(
                admission.get("decisions"), list
            ):
                raise EvidenceError("report admission decisions are invalid")
            expected_blocked = any(
                isinstance(decision, dict)
                and decision.get("status") in {"active", "expired"}
                and decision.get("severity") in severity_rank
                and severity_rank[decision["severity"]] >= threshold
                for decision in admission["decisions"]
            )
        else:
            findings = report["findings"]
            expected_blocked = any(
                isinstance(finding, dict)
                and finding.get("severity") in severity_rank
                and severity_rank[finding["severity"]] >= threshold
                for finding in findings
            )
        expected_gate = "blocked" if expected_blocked else "pass"
    if result["gate"] != expected_gate:
        raise EvidenceError("bundle gate result does not match the report")
    actual_inputs = {
        name for name in files if name.startswith("inputs/")
    }
    if actual_inputs != set(expected_inputs):
        raise EvidenceError("bundle control inputs do not match the report")
    for name, digest in expected_inputs.items():
        if _digest_bytes(files[name]) != digest:
            raise EvidenceError(f"{name} does not match the report digest")
        _load_json(files[name], label=name)
    if "scope" in report:
        try:
            verified_scope = parse_scope_plan(files["inputs/scope-plan.json"])
        except ScopePlanError as error:
            raise EvidenceError(f"invalid bundled scope plan: {error}") from error
        if verified_scope.metadata() != report["scope"]:
            raise EvidenceError(
                "bundled scope plan does not match report scope metadata"
            )

    sbom = _plain_object(
        _load_json(files["sbom.spdx.json"], label="sbom.spdx.json"),
        label="SPDX document",
        fields=frozenset(
            {
                "spdxVersion",
                "dataLicense",
                "SPDXID",
                "name",
                "documentNamespace",
                "creationInfo",
                "packages",
                "files",
                "relationships",
            }
        ),
    )
    if (
        sbom["spdxVersion"] != "SPDX-2.3"
        or sbom["dataLicense"] != "CC0-1.0"
        or sbom["SPDXID"] != "SPDXRef-DOCUMENT"
        or not isinstance(sbom["files"], list)
        or len(sbom["files"]) != len(report["manifest"]["files"])
        or sbom["creationInfo"].get("created")
        != created_on.isoformat() + "T00:00:00Z"
    ):
        raise EvidenceError("SPDX inventory contract is invalid")
    manifest_by_path = {
        item["path"]: item["sha256"]
        for item in report["manifest"]["files"]
    }
    spdx_by_path: dict[str, str] = {}
    for item in sbom["files"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("fileName"), str)
            or not item["fileName"].startswith("./")
            or not isinstance(item.get("checksums"), list)
            or len(item["checksums"]) != 1
        ):
            raise EvidenceError("SPDX file entry is invalid")
        checksum = item["checksums"][0]
        if checksum.get("algorithm") != "SHA256":
            raise EvidenceError("SPDX file checksum algorithm is invalid")
        spdx_by_path[item["fileName"][2:]] = checksum.get("checksumValue")
    if spdx_by_path != manifest_by_path:
        raise EvidenceError("SPDX inventory does not match the report manifest")

    canonical_predicate = _json_bytes(predicate)
    if files["bundle.json"] != canonical_predicate:
        raise EvidenceError("bundle.json is not canonically rendered")
    if files["report.json"] != _json_bytes(report):
        raise EvidenceError("report.json is not canonically rendered")
    if files["sbom.spdx.json"] != _json_bytes(sbom):
        raise EvidenceError("sbom.spdx.json is not canonically rendered")

    return EvidenceVerification(
        predicate=predicate,
        sbom=sbom,
        summary={
            "schema_version": BUNDLE_SCHEMA_VERSION,
            "valid": True,
            "gate": result["gate"],
            "component": component,
            "tool": tool,
            "manifest_digest": subject["manifest_digest"],
            "coverage_digest": subject["coverage_digest"],
            "policy_digest": result["policy_digest"],
            "files": len(files),
            "source_files_included": False,
            "dependency_resolution": "not-performed",
        },
    )


def verify_evidence_bundle(
    path: str | os.PathLike[str],
) -> EvidenceVerification:
    """Verify an untrusted bundle and normalize structural failures."""

    try:
        return _verify_evidence_bundle(path)
    except EvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError) as error:
        raise EvidenceError(
            "evidence bundle contains an invalid nested contract"
        ) from error
