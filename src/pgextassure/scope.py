"""Digest-bound scan roots and explicit filesystem exclusions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


MAX_SCOPE_PLAN_BYTES = 1024 * 1024
MAX_SCOPE_ROOTS = 64
MAX_SCOPE_EXCLUSIONS = 4096
MAX_SCOPE_PATH_BYTES = 4096
MAX_SCOPE_PATH_DEPTH = 64
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ScopePlanError(ValueError):
    """A scope plan is malformed, stale, or unsafe."""


@dataclass(frozen=True, slots=True)
class ScopeExclusion:
    path: str
    kind: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "kind": self.kind, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class ScopePlan:
    digest: str
    roots: tuple[str, ...]
    exclusions: tuple[ScopeExclusion, ...]

    def metadata(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "plan": {"algorithm": "sha256", "digest": self.digest},
            "roots": list(self.roots),
            "exclusions": [item.to_dict() for item in self.exclusions],
        }


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ScopePlanError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _object(
    value: object,
    *,
    label: str,
    fields: frozenset[str],
) -> dict[str, object]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise ScopePlanError(f"{label} must contain exactly {sorted(fields)}")
    return value


def _path(value: object, *, label: str, allow_dot: bool) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ScopePlanError(f"{label} must be a POSIX relative path")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ScopePlanError(f"{label} must be valid UTF-8") from error
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts:
        raise ScopePlanError(f"{label} must stay inside the scan root")
    normalized = parsed.as_posix()
    if normalized != value:
        raise ScopePlanError(f"{label} must use its canonical POSIX spelling")
    if normalized == "." and not allow_dot:
        raise ScopePlanError(f"{label} must name an entry")
    if (
        len(parsed.parts) > MAX_SCOPE_PATH_DEPTH
        or len(normalized.encode("utf-8")) > MAX_SCOPE_PATH_BYTES
    ):
        raise ScopePlanError(f"{label} exceeds the path limit")
    return normalized


def _read(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ScopePlanError(f"cannot inspect scope plan: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size > MAX_SCOPE_PLAN_BYTES
    ):
        raise ScopePlanError("scope plan must be a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ScopePlanError("scope plan must remain a regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(MAX_SCOPE_PLAN_BYTES + 1)
    except ScopePlanError:
        raise
    except OSError as error:
        raise ScopePlanError(f"cannot read scope plan: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_SCOPE_PLAN_BYTES or b"\x00" in raw:
        raise ScopePlanError("scope plan exceeds its safe input boundary")
    return raw


def parse_scope_plan(raw: bytes) -> ScopePlan:
    """Parse already-read exact plan bytes through the strict contract."""

    if len(raw) > MAX_SCOPE_PLAN_BYTES or b"\x00" in raw:
        raise ScopePlanError("scope plan exceeds its safe input boundary")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ScopePlanError(f"invalid scope plan JSON: {error}") from error
    document = _object(
        parsed,
        label="scope plan",
        fields=frozenset({"schema_version", "roots", "exclusions"}),
    )
    if document["schema_version"] != "1.0":
        raise ScopePlanError("scope plan schema_version must be '1.0'")
    raw_roots = document["roots"]
    if (
        not isinstance(raw_roots, list)
        or not raw_roots
        or len(raw_roots) > MAX_SCOPE_ROOTS
    ):
        raise ScopePlanError("scope plan roots must be a bounded non-empty list")
    roots = tuple(
        sorted({_path(value, label="scope root", allow_dot=True) for value in raw_roots})
    )
    if len(roots) != len(raw_roots):
        raise ScopePlanError("scope plan roots must be unique")
    root_paths = [PurePosixPath(root) for root in roots]
    for index, root in enumerate(root_paths):
        for other in root_paths[index + 1 :]:
            if root == PurePosixPath(".") or other == PurePosixPath("."):
                raise ScopePlanError("scope plan roots must not overlap")
            if root in other.parents or other in root.parents:
                raise ScopePlanError("scope plan roots must not overlap")

    raw_exclusions = document["exclusions"]
    if not isinstance(raw_exclusions, list) or len(raw_exclusions) > MAX_SCOPE_EXCLUSIONS:
        raise ScopePlanError("scope plan exclusions must be a bounded list")
    exclusions: list[ScopeExclusion] = []
    seen: set[str] = set()
    for index, value in enumerate(raw_exclusions):
        item = _object(
            value,
            label=f"scope exclusion {index}",
            fields=frozenset({"path", "kind", "sha256"}),
        )
        entry_path = _path(
            item["path"],
            label=f"scope exclusion {index} path",
            allow_dot=False,
        )
        kind = item["kind"]
        digest = item["sha256"]
        if kind not in {"regular", "symlink"}:
            raise ScopePlanError(f"scope exclusion {index} kind is invalid")
        if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
            raise ScopePlanError(f"scope exclusion {index} sha256 is invalid")
        if entry_path in seen:
            raise ScopePlanError(f"duplicate scope exclusion {entry_path!r}")
        if not any(
            root == "." or PurePosixPath(root) in PurePosixPath(entry_path).parents
            for root in roots
        ):
            raise ScopePlanError(f"scope exclusion {entry_path!r} is outside roots")
        seen.add(entry_path)
        exclusions.append(ScopeExclusion(entry_path, kind, digest))
    return ScopePlan(
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        roots=roots,
        exclusions=tuple(sorted(exclusions, key=lambda item: item.path)),
    )


def load_scope_plan(path: str | os.PathLike[str]) -> ScopePlan:
    return parse_scope_plan(_read(Path(path)))
