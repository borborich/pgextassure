"""Filesystem orchestration for PgExtAssure's non-executing static scanner."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Iterable

from .graph import scan_update_graph
from .models import (
    Finding,
    ManifestFile,
    ScanManifest,
    ScanReport,
    build_summary,
)
from .rules import (
    ControlDocument,
    parse_control,
    scan_c,
    scan_cargo,
    scan_control,
    scan_rust,
    scan_sql,
)
from .source import canonical_json_bytes, sha256_hex
from ._version import RELEASE_VERSION


TOOL_VERSION = RELEASE_VERSION
RULESET_VERSION = "2026-07-28.3"
SUPPORTED_SUFFIXES = frozenset({".control", ".sql", ".c", ".h", ".rs"})
SUPPORTED_FILENAMES = frozenset({"Cargo.toml"})
MAX_FILES = 25_000
MAX_ENTRIES = 100_000
MAX_DIRECTORIES = 10_000
MAX_PATH_DEPTH = 64
MAX_RELATIVE_PATH_BYTES = 4_096
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FINDINGS = 10_000


class ScanError(RuntimeError):
    """Base error for a scan that could not be completed."""


class ScanInputError(ScanError):
    """The requested path is missing or not a supported filesystem object."""


def is_supported(path: Path) -> bool:
    name = path.name.casefold()
    return (
        path.name in SUPPORTED_FILENAMES
        or path.suffix.casefold() in SUPPORTED_SUFFIXES
        or name.endswith(".control.in")
        or name.endswith(".sql.in")
    )


def _is_control(path: Path) -> bool:
    name = path.name.casefold()
    return name.endswith(".control") or name.endswith(".control.in")


def _is_sql(path: Path) -> bool:
    name = path.name.casefold()
    return name.endswith(".sql") or name.endswith(".sql.in")


def _sql_artifact_name(path: Path) -> str:
    name = path.name
    return name[:-3] if name.casefold().endswith(".sql.in") else name


def _control_script_roots(
    control: ControlDocument,
) -> tuple[tuple[str, ...], ...]:
    """Return safe source-tree locations that may hold versioned artifacts."""

    parent = PurePosixPath(control.path).parent
    roots = {parent.parts}
    configured = control.values.get("directory", "").strip()
    configured_path = PurePosixPath(configured)
    if (
        configured
        and not configured_path.is_absolute()
        and ".." not in configured_path.parts
        and not any(marker in configured for marker in ("$", "@"))
    ):
        # PostgreSQL resolves a relative ``directory`` from SHAREDIR, while
        # source trees also commonly place the control at their package root.
        # Cover both layouts without allowing the value to escape the scan.
        roots.add((parent / configured_path).parts)
        install_base = parent.parent if parent.parts else parent
        roots.add((install_base / configured_path).parts)
    return tuple(sorted(roots))


def _secondary_control_candidates(
    document: ControlDocument,
    controls: Iterable[ControlDocument],
) -> list[ControlDocument]:
    """Resolve a version-specific control to one primary control."""

    secondary_parent = PurePosixPath(document.path).parent.parts
    ranked: list[tuple[tuple[int, int], ControlDocument]] = []
    for control in controls:
        if control.extension != document.extension:
            continue
        roots = _control_script_roots(control)
        exact = [root for root in roots if root == secondary_parent]
        descendants = [
            root
            for root in roots
            if secondary_parent[: len(root)] == root
        ]
        if exact:
            score = (2, max(len(root) for root in exact))
        elif descendants:
            score = (1, max(len(root) for root in descendants))
        else:
            continue
        ranked.append((score, control))
    if not ranked:
        return []
    best = max(score for score, _control in ranked)
    return [control for score, control in ranked if score == best]


def _is_extension_sql(
    relative: str,
    controls: Iterable[ControlDocument],
    *,
    scan_all: bool,
) -> bool:
    if scan_all:
        return True
    path = Path(relative)
    artifact_name = _sql_artifact_name(path)
    for control in controls:
        if artifact_name.startswith(f"{control.extension}--"):
            return True
        if artifact_name != f"{control.extension}.sql":
            continue
        # A matching extension.sql.in is a build template even when projects
        # keep generated inputs in a sql/ directory away from the control file.
        if path.name.casefold().endswith(".sql.in"):
            return True
        # A plain extension.sql is commonly a build input when it sits beside
        # extension.control. Do not confuse sql/extension.sql regression tests
        # with an install artifact.
        if Path(control.path).parent == path.parent:
            return True
    return False


def _discover(path: Path) -> tuple[Path, list[Path]]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise ScanInputError(f"scan path does not exist: {path}")
    except OSError as error:
        raise ScanError(f"cannot inspect scan path {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise ScanInputError(f"refusing symlink scan root: {path}")
    if stat.S_ISREG(metadata.st_mode):
        if not is_supported(path):
            raise ScanInputError(f"unsupported input file: {path}")
        _validate_relative_path(path.name)
        return path.parent, [path]
    if not stat.S_ISDIR(metadata.st_mode):
        raise ScanInputError(f"scan path is neither a file nor directory: {path}")

    def walk_error(error: OSError) -> None:
        location = error.filename or path
        raise ScanError(f"cannot traverse {location}: {error}") from error

    discovered: list[Path] = []
    entries_seen = 0
    directories_seen = 1
    for directory, dirnames, filenames in os.walk(
        path,
        followlinks=False,
        onerror=walk_error,
    ):
        entries_seen += len(dirnames) + len(filenames)
        if entries_seen > MAX_ENTRIES:
            raise ScanInputError(
                f"scan exceeds the {MAX_ENTRIES}-entry filesystem limit"
            )
        directories_seen += len(dirnames)
        if directories_seen > MAX_DIRECTORIES:
            raise ScanInputError(
                f"scan exceeds the {MAX_DIRECTORIES}-directory limit"
            )

        retained_directories: list[str] = []
        for name in sorted(dirnames):
            candidate = Path(directory) / name
            relative = _relative(path, candidate)
            _validate_relative_path(relative)
            try:
                candidate_metadata = candidate.lstat()
            except OSError as error:
                raise ScanError(f"cannot inspect {candidate}: {error}") from error
            if stat.S_ISLNK(candidate_metadata.st_mode):
                raise ScanInputError(
                    f"refusing symlinked directory in scan tree: "
                    f"{relative}"
                )
            retained_directories.append(name)
        dirnames[:] = retained_directories

        for name in sorted(filenames):
            candidate = Path(directory) / name
            relative = _relative(path, candidate)
            _validate_relative_path(relative)
            if not is_supported(candidate):
                continue
            try:
                candidate_metadata = candidate.lstat()
            except OSError as error:
                raise ScanError(f"cannot inspect {candidate}: {error}") from error
            if stat.S_ISLNK(candidate_metadata.st_mode):
                raise ScanInputError(
                    f"refusing symlinked supported source file: {relative}"
                )
            if not stat.S_ISREG(candidate_metadata.st_mode):
                raise ScanInputError(
                    f"refusing non-regular source file: {relative}"
                )
            discovered.append(candidate)
            if len(discovered) > MAX_FILES:
                raise ScanInputError(
                    f"scan exceeds the {MAX_FILES} supported-file limit"
                )
    if not discovered:
        raise ScanInputError(f"no supported source files found under: {path}")
    return path, discovered


def _relative(root: Path, candidate: Path) -> str:
    try:
        return candidate.relative_to(root).as_posix()
    except ValueError:
        return candidate.name


def _validate_relative_path(relative: str) -> None:
    """Bound path metadata before traversing or retaining a tree entry."""

    depth = len(Path(relative).parts)
    if depth > MAX_PATH_DEPTH:
        raise ScanInputError(
            f"{relative} exceeds the {MAX_PATH_DEPTH}-component "
            "relative path depth limit"
        )
    encoded_length = len(relative.encode("utf-8", errors="surrogatepass"))
    if encoded_length > MAX_RELATIVE_PATH_BYTES:
        raise ScanInputError(
            f"{relative} exceeds the {MAX_RELATIVE_PATH_BYTES}-byte "
            "relative path limit"
        )


def _deduplicate(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    unique: dict[
        tuple[str, str, int | None, str, str, str], Finding
    ] = {}
    for finding in findings:
        key = (
            finding.rule_id,
            finding.path,
            finding.line,
            finding.message,
            finding.evidence,
            finding.capability,
        )
        unique[key] = finding
    return tuple(sorted(unique.values(), key=Finding.sort_key))


def _read_source(candidate: Path, relative: str, remaining_bytes: int) -> bytes:
    """Read one regular file through a bounded, non-following descriptor."""

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ScanInputError(f"refusing non-regular source file: {relative}")
        if metadata.st_size > MAX_FILE_BYTES:
            raise ScanInputError(
                f"{relative} exceeds the {MAX_FILE_BYTES}-byte per-file limit"
            )
        if metadata.st_size > remaining_bytes:
            raise ScanInputError(
                f"scan exceeds the {MAX_TOTAL_BYTES}-byte total input limit"
            )

        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(min(MAX_FILE_BYTES, remaining_bytes) + 1)
    except ScanInputError:
        raise
    except OSError as error:
        raise ScanError(f"cannot read {candidate}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if len(raw) > MAX_FILE_BYTES:
        raise ScanInputError(
            f"{relative} exceeds the {MAX_FILE_BYTES}-byte per-file limit"
        )
    if len(raw) > remaining_bytes:
        raise ScanInputError(
            f"scan exceeds the {MAX_TOTAL_BYTES}-byte total input limit"
        )
    return raw


def scan_path(path: str | os.PathLike[str]) -> ScanReport:
    """Statically scan ``path`` without importing, compiling, or executing it."""

    requested = Path(path)
    root, files = _discover(requested)
    manifest_files: list[ManifestFile] = []
    contents: dict[str, str] = {}
    total_bytes = 0
    for candidate in files:
        relative = _relative(root, candidate)
        try:
            relative.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ScanInputError(
                "supported source path is not valid UTF-8"
            ) from error
        raw = _read_source(candidate, relative, MAX_TOTAL_BYTES - total_bytes)
        total_bytes += len(raw)
        if b"\x00" in raw:
            raise ScanInputError(f"binary data found in supported source file: {relative}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ScanInputError(f"source file is not UTF-8: {relative}") from error
        manifest_files.append(
            ManifestFile(path=relative, size=len(raw), sha256=sha256_hex(raw))
        )
        contents[relative] = text

    manifest_files.sort(key=lambda item: item.path)
    manifest_payload = [item.to_dict() for item in manifest_files]
    manifest = ScanManifest(
        algorithm="sha256",
        digest="sha256:" + sha256_hex(canonical_json_bytes(manifest_payload)),
        files=tuple(manifest_files),
    )

    controls: list[ControlDocument] = []
    secondary_controls: list[ControlDocument] = []
    findings: list[Finding] = []
    sql_paths: list[str] = []

    def extend_findings(batch: Iterable[Finding]) -> None:
        additions = list(batch)
        if len(findings) + len(additions) > MAX_FINDINGS:
            raise ScanInputError(
                f"scan exceeds the {MAX_FINDINGS}-finding report limit"
            )
        findings.extend(additions)

    for relative in sorted(contents):
        path_object = Path(relative)
        if not _is_control(path_object):
            continue
        document = parse_control(relative, contents[relative])
        if document.secondary_version is None:
            controls.append(document)
        else:
            secondary_controls.append(document)

    for document in controls:
        extend_findings(scan_control(document))

    for document in secondary_controls:
        candidates = _secondary_control_candidates(document, controls)
        if len(candidates) == 1:
            primary = candidates[0]
            effective = replace(
                document,
                values={**primary.values, **document.values},
                lines={**primary.lines, **document.lines},
            )
            extend_findings(
                scan_control(
                    effective,
                    explicit_keys=frozenset(document.values),
                )
            )
        else:
            # A standalone or ambiguous secondary control cannot safely inherit
            # privilege defaults, so retain the normal fail-closed scan.
            extend_findings(scan_control(document))

    scan_all_sql = requested.is_file() or not controls
    for relative in sorted(contents):
        text = contents[relative]
        path_object = Path(relative)
        suffix = path_object.suffix.casefold()
        if _is_control(path_object):
            continue
        if _is_sql(path_object) and _is_extension_sql(
            relative, controls, scan_all=scan_all_sql
        ):
            sql_paths.append(relative)
            extend_findings(scan_sql(relative, text))
        elif suffix in {".c", ".h"}:
            extend_findings(scan_c(relative, text))
        elif suffix == ".rs":
            extend_findings(scan_rust(relative, text))
        elif path_object.name == "Cargo.toml":
            extend_findings(scan_cargo(relative, text))

    extend_findings(
        scan_update_graph(
            sql_paths,
            controls,
            max_findings=MAX_FINDINGS - len(findings) + 1,
        )
    )
    ordered = _deduplicate(findings)
    return ScanReport(
        schema_version="1.0",
        tool={
            "name": "pgextassure",
            "version": TOOL_VERSION,
            "ruleset_version": RULESET_VERSION,
        },
        manifest=manifest,
        summary=build_summary(len(manifest_files), ordered),
        findings=ordered,
    )
