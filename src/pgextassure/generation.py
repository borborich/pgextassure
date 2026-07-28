"""Auditable declarations for build-generated SQL and control artifacts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Iterable

from .source import sha256_hex


MAX_PLAN_BYTES = 1024 * 1024
MAX_ARTIFACTS = 1024
MAX_INPUTS = 4096
MAX_INPUT_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 64 * 1024 * 1024
MAX_RENDERED_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_RENDERED_BYTES = 64 * 1024 * 1024
MAX_SUBSTITUTIONS = 256
MAX_SUBSTITUTION_VALUE_BYTES = 4096
MAX_PATH_DEPTH = 64
MAX_PATH_BYTES = 4096
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SUBSTITUTION_PATTERN = re.compile(
    r"(?:@[A-Z][A-Z0-9_]*@|[A-Z][A-Z0-9_]*)\Z"
)


class GenerationPlanError(ValueError):
    """A generation declaration is malformed, stale, or unsafe."""


@dataclass(frozen=True, slots=True)
class GenerationInput:
    path: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class GeneratedArtifact:
    path: str
    inputs: tuple[GenerationInput, ...]
    template: str | None
    substitutions: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class GenerationPlan:
    digest: str
    artifacts: tuple[GeneratedArtifact, ...]


@dataclass(frozen=True, slots=True)
class GenerationResult:
    rendered_contents: dict[str, str]
    declared_sql_paths: tuple[str, ...]
    replaced_templates: frozenset[str]
    metadata: dict[str, Any]


def _safe_relative_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise GenerationPlanError(f"{label} must be a POSIX relative path")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise GenerationPlanError(f"{label} must be valid UTF-8") from error
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise GenerationPlanError(f"{label} must stay inside the scan root")
    normalized = path.as_posix()
    if normalized in {"", "."}:
        raise GenerationPlanError(f"{label} must name a file")
    if len(path.parts) > MAX_PATH_DEPTH:
        raise GenerationPlanError(
            f"{label} exceeds the {MAX_PATH_DEPTH}-component depth limit"
        )
    if len(normalized.encode("utf-8")) > MAX_PATH_BYTES:
        raise GenerationPlanError(
            f"{label} exceeds the {MAX_PATH_BYTES}-byte path limit"
        )
    return normalized


def _object(
    value: object,
    *,
    label: str,
    allowed: frozenset[str],
    required: frozenset[str],
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise GenerationPlanError(f"{label} must be an object")
    keys = frozenset(value)
    unknown = keys - allowed
    missing = required - keys
    if unknown:
        raise GenerationPlanError(
            f"{label} contains unknown field {sorted(unknown)[0]!r}"
        )
    if missing:
        raise GenerationPlanError(
            f"{label} is missing field {sorted(missing)[0]!r}"
        )
    return value


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GenerationPlanError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_plan(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GenerationPlanError(f"cannot inspect generation plan: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise GenerationPlanError("generation plan must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise GenerationPlanError("generation plan must be a regular file")
    if metadata.st_size > MAX_PLAN_BYTES:
        raise GenerationPlanError(
            f"generation plan exceeds the {MAX_PLAN_BYTES}-byte limit"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise GenerationPlanError(
                "generation plan must remain a regular file"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(MAX_PLAN_BYTES + 1)
    except GenerationPlanError:
        raise
    except OSError as error:
        raise GenerationPlanError(f"cannot read generation plan: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_PLAN_BYTES:
        raise GenerationPlanError(
            f"generation plan exceeds the {MAX_PLAN_BYTES}-byte limit"
        )
    return raw


def load_generation_plan(path: str | os.PathLike[str]) -> GenerationPlan:
    """Load and strictly validate a non-executing artifact declaration."""

    raw = _read_plan(Path(path))
    if b"\x00" in raw:
        raise GenerationPlanError("generation plan contains binary data")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GenerationPlanError("generation plan is not UTF-8") from error
    try:
        parsed = json.loads(text, object_pairs_hook=_pairs_object)
    except GenerationPlanError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise GenerationPlanError(f"invalid generation plan JSON: {error}") from error

    document = _object(
        parsed,
        label="generation plan",
        allowed=frozenset({"schema_version", "artifacts"}),
        required=frozenset({"schema_version", "artifacts"}),
    )
    if document["schema_version"] != "1.0":
        raise GenerationPlanError("generation plan schema_version must be '1.0'")
    raw_artifacts = document["artifacts"]
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise GenerationPlanError("generation plan artifacts must be a non-empty list")
    if len(raw_artifacts) > MAX_ARTIFACTS:
        raise GenerationPlanError(
            f"generation plan exceeds the {MAX_ARTIFACTS}-artifact limit"
        )

    artifacts: list[GeneratedArtifact] = []
    targets: set[str] = set()
    total_inputs = 0
    for index, raw_artifact in enumerate(raw_artifacts):
        label = f"artifact {index}"
        artifact = _object(
            raw_artifact,
            label=label,
            allowed=frozenset(
                {"path", "inputs", "template", "substitutions"}
            ),
            required=frozenset({"path", "inputs"}),
        )
        target = _safe_relative_path(artifact["path"], label=f"{label} path")
        if not target.endswith((".sql", ".control")):
            raise GenerationPlanError(
                f"{label} path must end in .sql or .control"
            )
        if target in targets:
            raise GenerationPlanError(f"duplicate generated artifact {target!r}")
        targets.add(target)

        raw_inputs = artifact["inputs"]
        if not isinstance(raw_inputs, list) or not raw_inputs:
            raise GenerationPlanError(f"{label} inputs must be a non-empty list")
        total_inputs += len(raw_inputs)
        if total_inputs > MAX_INPUTS:
            raise GenerationPlanError(
                f"generation plan exceeds the {MAX_INPUTS}-input limit"
            )
        inputs: list[GenerationInput] = []
        input_paths: set[str] = set()
        for input_index, raw_input in enumerate(raw_inputs):
            input_label = f"{label} input {input_index}"
            item = _object(
                raw_input,
                label=input_label,
                allowed=frozenset({"path", "sha256"}),
                required=frozenset({"path", "sha256"}),
            )
            source_path = _safe_relative_path(
                item["path"],
                label=f"{input_label} path",
            )
            digest = item["sha256"]
            if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(
                digest
            ):
                raise GenerationPlanError(
                    f"{input_label} sha256 must be sha256:<64 lowercase hex>"
                )
            if source_path in input_paths:
                raise GenerationPlanError(
                    f"{label} repeats input {source_path!r}"
                )
            input_paths.add(source_path)
            inputs.append(GenerationInput(source_path, digest))

        raw_template = artifact.get("template")
        template = (
            _safe_relative_path(raw_template, label=f"{label} template")
            if raw_template is not None
            else None
        )
        if template is not None and template not in input_paths:
            raise GenerationPlanError(
                f"{label} template must also appear in inputs"
            )
        if target.endswith(".control") and template is None:
            raise GenerationPlanError(
                f"{label} control artifact requires a template"
            )

        raw_substitutions = artifact.get("substitutions", {})
        if not isinstance(raw_substitutions, dict):
            raise GenerationPlanError(f"{label} substitutions must be an object")
        if len(raw_substitutions) > MAX_SUBSTITUTIONS:
            raise GenerationPlanError(
                f"{label} exceeds the {MAX_SUBSTITUTIONS}-substitution limit"
            )
        if raw_substitutions and template is None:
            raise GenerationPlanError(
                f"{label} substitutions require a template"
            )
        substitutions: list[tuple[str, str]] = []
        for token, replacement in raw_substitutions.items():
            if not _SUBSTITUTION_PATTERN.fullmatch(token):
                raise GenerationPlanError(
                    f"{label} substitution token {token!r} is not supported"
                )
            if not isinstance(replacement, str):
                raise GenerationPlanError(
                    f"{label} substitution {token!r} must be a string"
                )
            try:
                encoded = replacement.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise GenerationPlanError(
                    f"{label} substitution {token!r} is not valid UTF-8"
                ) from error
            if (
                len(encoded) > MAX_SUBSTITUTION_VALUE_BYTES
                or any(ord(character) < 0x20 for character in replacement)
                or "\x7f" in replacement
            ):
                raise GenerationPlanError(
                    f"{label} substitution {token!r} is unsafe or too large"
                )
            substitutions.append((token, replacement))
        artifacts.append(
            GeneratedArtifact(
                path=target,
                inputs=tuple(inputs),
                template=template,
                substitutions=tuple(sorted(substitutions)),
            )
        )

    return GenerationPlan(
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        artifacts=tuple(artifacts),
    )


def _read_input(root: Path, relative: str) -> bytes:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved_root = root.resolve(strict=True)
        candidate.resolve(strict=True).relative_to(resolved_root)
        metadata = candidate.lstat()
    except (OSError, ValueError) as error:
        raise GenerationPlanError(
            f"generation input {relative!r} is missing or escapes the scan root"
        ) from error
    if stat.S_ISLNK(metadata.st_mode):
        raise GenerationPlanError(
            f"generation input {relative!r} must not be a symlink"
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise GenerationPlanError(
            f"generation input {relative!r} must be a regular file"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise GenerationPlanError(
                f"generation input {relative!r} changed type while reading"
            )
        if opened.st_size > MAX_INPUT_FILE_BYTES:
            raise GenerationPlanError(
                f"generation input {relative!r} exceeds the input byte limit"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(MAX_INPUT_FILE_BYTES + 1)
    except GenerationPlanError:
        raise
    except OSError as error:
        raise GenerationPlanError(
            f"cannot read generation input {relative!r}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_INPUT_FILE_BYTES:
        raise GenerationPlanError(
            f"generation input {relative!r} exceeds the input byte limit"
        )
    return raw


def _render_template(
    raw: bytes,
    substitutions: Iterable[tuple[str, str]],
    *,
    path: str,
) -> str:
    if b"\x00" in raw:
        raise GenerationPlanError(
            f"generation template {path!r} contains binary data"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GenerationPlanError(
            f"generation template {path!r} is not UTF-8"
        ) from error
    replacements = dict(substitutions)
    for token in replacements:
        if token not in text:
            raise GenerationPlanError(
                f"generation template {path!r} does not contain token {token!r}"
            )
    if replacements:
        projected_size = len(raw)
        for token, replacement in replacements.items():
            projected_size += text.count(token) * (
                len(replacement.encode("utf-8")) - len(token.encode("utf-8"))
            )
            if projected_size > MAX_RENDERED_FILE_BYTES:
                raise GenerationPlanError(
                    f"rendered generation template {path!r} exceeds the byte limit"
                )
        pattern = re.compile(
            "|".join(
                re.escape(token)
                for token in sorted(replacements, key=lambda item: (-len(item), item))
            )
        )
        text = pattern.sub(lambda match: replacements[match.group(0)], text)
    if len(text.encode("utf-8")) > MAX_RENDERED_FILE_BYTES:
        raise GenerationPlanError(
            f"rendered generation template {path!r} exceeds the byte limit"
        )
    return text


def materialize_generation_plan(
    plan: GenerationPlan,
    root: Path,
    *,
    occupied_paths: Iterable[str],
) -> GenerationResult:
    """Verify pinned inputs and materialize only literal template substitutions."""

    occupied = set(occupied_paths)
    cache: dict[str, bytes] = {}
    total_input_bytes = 0
    rendered: dict[str, str] = {}
    declared_sql: list[str] = []
    replaced_templates: set[str] = set()
    metadata_artifacts: list[dict[str, Any]] = []
    total_rendered_bytes = 0

    for artifact in plan.artifacts:
        if artifact.path in occupied:
            raise GenerationPlanError(
                f"generated artifact {artifact.path!r} conflicts with a real source"
            )
        verified_inputs: list[dict[str, str]] = []
        for source in artifact.inputs:
            if source.path not in cache:
                raw = _read_input(root, source.path)
                total_input_bytes += len(raw)
                if total_input_bytes > MAX_TOTAL_INPUT_BYTES:
                    raise GenerationPlanError(
                        "generation inputs exceed the total byte limit"
                    )
                cache[source.path] = raw
            actual = "sha256:" + sha256_hex(cache[source.path])
            if actual != source.sha256:
                raise GenerationPlanError(
                    f"generation input digest mismatch for {source.path!r}"
                )
            verified_inputs.append(source.to_dict())

        artifact_metadata: dict[str, Any] = {
            "path": artifact.path,
            "mode": "declared",
            "inputs": verified_inputs,
        }
        if artifact.path.casefold().endswith(".sql"):
            declared_sql.append(artifact.path)
        if artifact.template is not None:
            content = _render_template(
                cache[artifact.template],
                artifact.substitutions,
                path=artifact.template,
            )
            rendered[artifact.path] = content
            replaced_templates.add(artifact.template)
            encoded = content.encode("utf-8")
            total_rendered_bytes += len(encoded)
            if total_rendered_bytes > MAX_TOTAL_RENDERED_BYTES:
                raise GenerationPlanError(
                    "rendered generation artifacts exceed the total byte limit"
                )
            artifact_metadata.update(
                {
                    "mode": "rendered",
                    "template": artifact.template,
                    "substitution_tokens": [
                        token for token, _replacement in artifact.substitutions
                    ],
                    "rendered_size": len(encoded),
                    "rendered_sha256": "sha256:" + sha256_hex(encoded),
                }
            )
        metadata_artifacts.append(artifact_metadata)

    return GenerationResult(
        rendered_contents=rendered,
        declared_sql_paths=tuple(sorted(declared_sql)),
        replaced_templates=frozenset(replaced_templates),
        metadata={
            "plan": {
                "algorithm": "sha256",
                "digest": plan.digest,
            },
            "artifacts": metadata_artifacts,
        },
    )
