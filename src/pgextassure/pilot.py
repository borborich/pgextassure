"""Deterministic, non-extracting enterprise pilot handoff packages."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
import zipfile

from .signing import SigningError, _read_regular


PILOT_PACKAGE_SCHEMA_VERSION = "1.0"
PILOT_PACKAGE_TYPE = "pgextassure.enterprise-pilot-package"
PILOT_MANIFEST_NAME = "pilot-package.json"
MAX_PILOT_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_PILOT_FILE_BYTES = 64 * 1024 * 1024
MAX_PILOT_FILES = 64
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REQUIRED_FILES = frozenset(
    {
        "README.md",
        "acceptance-criteria.md",
        "enterprise-trust-policy.json",
        "evidence-verify.json",
        "pgextassure-admission-receipt.json",
        "pgextassure-evidence.zip",
        "pgextassure-public-key.pem",
        "pgextassure-signature.bin",
        "pgextassure-signature.json",
        "receipt-verify.json",
        "release-provenance.json",
        "release-SHA256SUMS",
        "security-questionnaire.md",
        "signature-verify.json",
        "verification.md",
    }
)
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"PuTTY-User-Key-File-",
)


class PilotPackageError(ValueError):
    """A pilot staging directory or package is malformed."""


@dataclass(frozen=True, slots=True)
class PilotPackage:
    archive: bytes
    manifest: dict[str, Any]
    summary: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PilotPackageVerification:
    manifest: dict[str, Any]
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


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PilotPackageError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _validate_name(name: str) -> None:
    if not _NAME_PATTERN.fullmatch(name):
        raise PilotPackageError(f"unsafe pilot package path {name!r}")


def _check_private_key(name: str, content: bytes) -> None:
    if any(marker in content for marker in _PRIVATE_KEY_MARKERS):
        raise PilotPackageError(
            f"pilot package file {name!r} contains private-key material"
        )


def _validate_required_files(names: frozenset[str]) -> tuple[str, str]:
    missing = _REQUIRED_FILES - names
    if missing:
        raise PilotPackageError(
            f"pilot package is missing {sorted(missing)[0]!r}"
        )
    wheels = sorted(name for name in names if name.endswith(".whl"))
    sdists = sorted(name for name in names if name.endswith(".tar.gz"))
    if len(wheels) != 1:
        raise PilotPackageError(
            "pilot package must contain exactly one PgExtAssure wheel"
        )
    if len(sdists) != 1:
        raise PilotPackageError(
            "pilot package must contain exactly one PgExtAssure source distribution"
        )
    if not wheels[0].startswith("pgextassure-"):
        raise PilotPackageError("pilot package wheel name is invalid")
    if not sdists[0].startswith("pgextassure-"):
        raise PilotPackageError("pilot package source distribution name is invalid")
    allowed = _REQUIRED_FILES | {wheels[0], sdists[0]}
    extras = names - allowed
    if extras:
        raise PilotPackageError(
            f"pilot package contains unexpected file {sorted(extras)[0]!r}"
        )
    return wheels[0], sdists[0]


def _release_checksums(
    raw: bytes,
    *,
    wheel_name: str,
    wheel_raw: bytes,
    sdist_name: str,
    sdist_raw: bytes,
) -> None:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise PilotPackageError("release-SHA256SUMS must be ASCII") from error
    expected = {
        wheel_name: hashlib.sha256(wheel_raw).hexdigest(),
        sdist_name: hashlib.sha256(sdist_raw).hexdigest(),
    }
    found: dict[str, str] = {}
    for index, line in enumerate(text.splitlines()):
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise PilotPackageError(
                f"release-SHA256SUMS line {index + 1} is invalid"
            )
        name = parts[1].removeprefix("*").removeprefix("./")
        if name in found:
            raise PilotPackageError(
                f"release-SHA256SUMS repeats {name!r}"
            )
        found[name] = parts[0]
    for name, digest in expected.items():
        if found.get(name) != digest:
            raise PilotPackageError(
                f"release-SHA256SUMS does not authenticate {name!r}"
            )


def _manifest(files: dict[str, bytes]) -> dict[str, Any]:
    return {
        "schema_version": PILOT_PACKAGE_SCHEMA_VERSION,
        "package_type": PILOT_PACKAGE_TYPE,
        "files": [
            {
                "path": name,
                "sha256": "sha256:" + hashlib.sha256(files[name]).hexdigest(),
                "size": len(files[name]),
            }
            for name in sorted(files)
        ],
    }


def _validate_files(files: dict[str, bytes]) -> tuple[str, str]:
    if not 1 <= len(files) <= MAX_PILOT_FILES:
        raise PilotPackageError(
            f"pilot package must contain 1..{MAX_PILOT_FILES} payload files"
        )
    total = 0
    for name, content in files.items():
        _validate_name(name)
        if name == PILOT_MANIFEST_NAME:
            raise PilotPackageError(
                f"{PILOT_MANIFEST_NAME!r} is reserved for the package manifest"
            )
        if len(content) > MAX_PILOT_FILE_BYTES:
            raise PilotPackageError(
                f"pilot package file {name!r} exceeds the safe size limit"
            )
        total += len(content)
        _check_private_key(name, content)
    if total > MAX_PILOT_PACKAGE_BYTES:
        raise PilotPackageError("pilot package payload exceeds the safe size limit")
    names = frozenset(files)
    wheel_name, sdist_name = _validate_required_files(names)
    _release_checksums(
        files["release-SHA256SUMS"],
        wheel_name=wheel_name,
        wheel_raw=files[wheel_name],
        sdist_name=sdist_name,
        sdist_raw=files[sdist_name],
    )
    return wheel_name, sdist_name


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name in sorted(files):
            information = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            information.compress_type = zipfile.ZIP_DEFLATED
            information.external_attr = 0o100644 << 16
            archive.writestr(information, files[name])
    return output.getvalue()


def create_pilot_package(
    staging_directory: str | os.PathLike[str],
) -> PilotPackage:
    """Create a deterministic, flat enterprise pilot handoff ZIP."""

    root = Path(staging_directory)
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise PilotPackageError(
            f"cannot inspect pilot staging directory: {error}"
        ) from error
    if root.is_symlink() or not stat.S_ISDIR(root_stat.st_mode):
        raise PilotPackageError(
            "pilot staging path must be a regular non-symlink directory"
        )
    files: dict[str, bytes] = {}
    try:
        entries = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise PilotPackageError(
            f"cannot enumerate pilot staging directory: {error}"
        ) from error
    for entry in entries:
        name = entry.name
        _validate_name(name)
        try:
            raw = _read_regular(
                entry,
                label=f"pilot package file {name!r}",
                maximum=MAX_PILOT_FILE_BYTES,
            )
        except SigningError as error:
            raise PilotPackageError(str(error)) from error
        files[name] = raw
    wheel_name, sdist_name = _validate_files(files)
    manifest = _manifest(files)
    archive_files = {**files, PILOT_MANIFEST_NAME: _json_bytes(manifest)}
    rendered = _zip_bytes(archive_files)
    if len(rendered) > MAX_PILOT_PACKAGE_BYTES:
        raise PilotPackageError("pilot package archive exceeds the safe size limit")
    return PilotPackage(
        archive=rendered,
        manifest=manifest,
        summary={
            "schema_version": PILOT_PACKAGE_SCHEMA_VERSION,
            "valid": True,
            "files": len(files),
            "archive_sha256": (
                "sha256:" + hashlib.sha256(rendered).hexdigest()
            ),
            "wheel": wheel_name,
            "source_distribution": sdist_name,
        },
    )


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except PilotPackageError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise PilotPackageError(f"invalid pilot package manifest: {error}") from error
    if not isinstance(parsed, dict):
        raise PilotPackageError("pilot package manifest must be an object")
    if set(parsed) != {"schema_version", "package_type", "files"}:
        raise PilotPackageError("pilot package manifest has an invalid schema")
    if (
        parsed["schema_version"] != PILOT_PACKAGE_SCHEMA_VERSION
        or parsed["package_type"] != PILOT_PACKAGE_TYPE
    ):
        raise PilotPackageError("unsupported pilot package manifest")
    entries = parsed["files"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_PILOT_FILES:
        raise PilotPackageError("pilot package manifest files are invalid")
    previous = ""
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise PilotPackageError(
                f"pilot package manifest entry {index} is invalid"
            )
        name = entry["path"]
        digest = entry["sha256"]
        size = entry["size"]
        if not isinstance(name, str):
            raise PilotPackageError(
                f"pilot package manifest entry {index} path is invalid"
            )
        _validate_name(name)
        if name <= previous:
            raise PilotPackageError(
                "pilot package manifest paths must be unique and sorted"
            )
        if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
            raise PilotPackageError(
                f"pilot package manifest entry {index} digest is invalid"
            )
        if type(size) is not int or not 0 <= size <= MAX_PILOT_FILE_BYTES:
            raise PilotPackageError(
                f"pilot package manifest entry {index} size is invalid"
            )
        previous = name
    if raw != _json_bytes(parsed):
        raise PilotPackageError("pilot package manifest is not canonical JSON")
    return parsed


def verify_pilot_package(
    package_path: str | os.PathLike[str],
) -> PilotPackageVerification:
    """Verify a pilot handoff ZIP without extracting it."""

    try:
        raw = _read_regular(
            package_path,
            label="enterprise pilot package",
            maximum=MAX_PILOT_PACKAGE_BYTES,
        )
    except SigningError as error:
        raise PilotPackageError(str(error)) from error
    try:
        archive = zipfile.ZipFile(BytesIO(raw), mode="r")
    except (OSError, zipfile.BadZipFile) as error:
        raise PilotPackageError(f"invalid enterprise pilot package: {error}") from error
    with archive:
        information = archive.infolist()
        names = [entry.filename for entry in information]
        if len(names) != len(set(names)):
            raise PilotPackageError("pilot package contains duplicate paths")
        if PILOT_MANIFEST_NAME not in names:
            raise PilotPackageError("pilot package manifest is missing")
        if len(names) > MAX_PILOT_FILES + 1:
            raise PilotPackageError("pilot package contains too many entries")
        if sum(entry.file_size for entry in information) > (
            MAX_PILOT_PACKAGE_BYTES + MAX_PILOT_FILE_BYTES
        ):
            raise PilotPackageError(
                "pilot package declared content exceeds the safe size limit"
            )
        files: dict[str, bytes] = {}
        manifest_raw: bytes | None = None
        for entry in information:
            _validate_name(entry.filename)
            if entry.is_dir() or entry.file_size > MAX_PILOT_FILE_BYTES:
                raise PilotPackageError(
                    f"pilot package entry {entry.filename!r} is unsafe"
                )
            if entry.compress_type not in {
                zipfile.ZIP_STORED,
                zipfile.ZIP_DEFLATED,
            }:
                raise PilotPackageError(
                    f"pilot package entry {entry.filename!r} uses unsafe compression"
                )
            try:
                content = archive.read(entry)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise PilotPackageError(
                    f"cannot read pilot package entry {entry.filename!r}: {error}"
                ) from error
            if len(content) != entry.file_size:
                raise PilotPackageError(
                    f"pilot package entry {entry.filename!r} is truncated"
                )
            if entry.filename == PILOT_MANIFEST_NAME:
                manifest_raw = content
            else:
                files[entry.filename] = content
    assert manifest_raw is not None
    _validate_files(files)
    manifest = _parse_manifest(manifest_raw)
    if manifest != _manifest(files):
        raise PilotPackageError(
            "pilot package payload does not match its manifest"
        )
    return PilotPackageVerification(
        manifest=manifest,
        summary={
            "schema_version": PILOT_PACKAGE_SCHEMA_VERSION,
            "valid": True,
            "files": len(files),
            "archive_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        },
    )
