#!/usr/bin/env python3
"""Generate a disclosure-safe public index from a normalized corpus run."""

from __future__ import annotations

import argparse
import csv
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUMMARY = (
    PROJECT_ROOT / "benchmark-results" / "public-corpus" / "summary.json"
)
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "benchmarks" / "public-corpus" / "manifest.tsv"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "benchmark-results" / "public-corpus" / "index"
)
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
CAPABILITY_PATTERN = re.compile(r"[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+\Z")
ERROR_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z")
GITHUB_URL_PATTERN = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git\Z"
)
MANIFEST_REQUIRED_FIELDS = (
    "repository",
    "url",
    "commit",
    "commit_date",
    "scan_path",
)
MANIFEST_OPTIONAL_FIELDS = ("generation_plan", "scope_plan")


class IndexError(RuntimeError):
    """The normalized corpus cannot safely produce a public index."""


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a deterministic, disclosure-safe public assurance index "
            "from an existing normalized corpus result."
        )
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=DEFAULT_SUMMARY,
        help="normalized public-corpus summary.json",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="tab-separated pinned corpus manifest",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="directory for index.json and index.md",
    )
    return parser.parse_args(argv)


def _read_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink():
        raise IndexError(f"{label} must not be a symlink")
    try:
        return path.read_bytes()
    except OSError as error:
        raise IndexError(f"cannot read {label}: {error}") from error


def _sha256(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _load_json_object(content: bytes) -> dict[str, object]:
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IndexError("normalized summary must be valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise IndexError("normalized summary must be a JSON object")
    return document


def _load_manifest(content: bytes) -> tuple[dict[str, str], ...]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IndexError("manifest must be valid UTF-8 TSV") from error
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    header = tuple(reader.fieldnames or ())
    if header[: len(MANIFEST_REQUIRED_FIELDS)] != MANIFEST_REQUIRED_FIELDS:
        raise IndexError("manifest has an unsupported header")
    optional = header[len(MANIFEST_REQUIRED_FIELDS) :]
    if any(field not in MANIFEST_OPTIONAL_FIELDS for field in optional):
        raise IndexError("manifest has an unsupported header")
    if len(set(header)) != len(header):
        raise IndexError("manifest header contains duplicate fields")

    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for row_number, row in enumerate(reader, start=2):
        if None in row:
            raise IndexError(f"manifest row {row_number}: too many fields")
        repository = row.get("repository", "")
        url = row.get("url", "")
        commit = row.get("commit", "")
        commit_date = row.get("commit_date", "")
        if not REPOSITORY_PATTERN.fullmatch(repository):
            raise IndexError(f"manifest row {row_number}: invalid repository")
        if repository in seen:
            raise IndexError(f"manifest row {row_number}: duplicate repository")
        if not GITHUB_URL_PATTERN.fullmatch(url):
            raise IndexError(f"manifest row {row_number}: invalid repository URL")
        if not COMMIT_PATTERN.fullmatch(commit):
            raise IndexError(f"manifest row {row_number}: invalid commit")
        try:
            date.fromisoformat(commit_date)
        except ValueError as error:
            raise IndexError(
                f"manifest row {row_number}: invalid commit date"
            ) from error
        record = {field: row.get(field, "-") or "-" for field in header}
        for field in MANIFEST_OPTIONAL_FIELDS:
            record.setdefault(field, "-")
        records.append(record)
        seen.add(repository)
    if not records:
        raise IndexError("manifest contains no repositories")
    return tuple(records)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndexError(f"{label} must be a non-empty string")
    return value


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IndexError(f"{label} must be a non-negative integer")
    return value


def _validate_no_evidence_payload(value: object, path: str = "summary") -> None:
    """Fail closed if a supposedly normalized input contains raw evidence."""

    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"evidence", "excerpt", "source_excerpt", "line_text"}:
                raise IndexError(f"{path} contains prohibited evidence field {key!r}")
            if key in {"findings", "root_causes"} and isinstance(
                child, (dict, list)
            ):
                raise IndexError(f"{path}.{key} contains a raw record collection")
            _validate_no_evidence_payload(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_no_evidence_payload(child, f"{path}[{index}]")


def _tool(document: Mapping[str, object]) -> dict[str, str]:
    raw = document.get("tool")
    if not isinstance(raw, dict):
        raise IndexError("summary.tool must be an object")
    name = _string(raw.get("name"), "summary.tool.name")
    version = _string(raw.get("version"), "summary.tool.version")
    ruleset = _string(
        raw.get("ruleset_version"), "summary.tool.ruleset_version"
    )
    if name != "pgextassure":
        raise IndexError("summary was not produced by pgextassure")
    if not VERSION_PATTERN.fullmatch(version):
        raise IndexError("summary.tool.version is not publication-safe")
    if not VERSION_PATTERN.fullmatch(ruleset):
        raise IndexError("summary.tool.ruleset_version is not publication-safe")
    return {"name": name, "version": version, "ruleset_version": ruleset}


def _project(
    manifest: Mapping[str, str],
    record: Mapping[str, object],
) -> dict[str, object]:
    repository = manifest["repository"]
    comparisons = (
        ("repository", repository),
        ("url", manifest["url"]),
        ("commit", manifest["commit"]),
        ("commit_date", manifest["commit_date"]),
        ("scan_path", manifest["scan_path"]),
    )
    for field, expected in comparisons:
        if record.get(field) != expected:
            raise IndexError(f"{repository}: summary {field} does not match manifest")
    for field in MANIFEST_OPTIONAL_FIELDS:
        if record.get(field, "-") != manifest[field]:
            raise IndexError(f"{repository}: summary {field} does not match manifest")

    status = record.get("status")
    project: dict[str, object] = {
        "name": repository,
        "repository_url": manifest["url"][:-4],
        "revision": manifest["commit"],
        "revision_date": manifest["commit_date"],
        "analysis_status": "completed" if status == "ok" else "not_completed",
        "coverage_controls": {
            "generation_plan_used": manifest["generation_plan"] != "-",
            "scope_plan_used": manifest["scope_plan"] != "-",
        },
    }
    if status == "ok":
        digest = _string(
            record.get("source_manifest_digest"),
            f"{repository}.source_manifest_digest",
        )
        if not DIGEST_PATTERN.fullmatch(digest):
            raise IndexError(f"{repository}: invalid source manifest digest")
        raw_capabilities = record.get("capabilities")
        if not isinstance(raw_capabilities, list) or not all(
            isinstance(item, str) and CAPABILITY_PATTERN.fullmatch(item)
            for item in raw_capabilities
        ):
            raise IndexError(f"{repository}: invalid capability profile")
        project.update(
            {
                "source_manifest_digest": digest,
                "files_analyzed": _nonnegative_integer(
                    record.get("files_scanned"), f"{repository}.files_scanned"
                ),
                "capability_profile": sorted(set(raw_capabilities)),
            }
        )
        generated = record.get("generated_artifacts", 0)
        project["coverage_controls"]["generated_artifacts_analyzed"] = (
            _nonnegative_integer(generated, f"{repository}.generated_artifacts")
        )
        if manifest["generation_plan"] != "-":
            generation_digest = _string(
                record.get("generation_plan_digest"),
                f"{repository}.generation_plan_digest",
            )
            if not DIGEST_PATTERN.fullmatch(generation_digest):
                raise IndexError(f"{repository}: invalid generation plan digest")
        if manifest["scope_plan"] != "-":
            scope_digest = _string(
                record.get("scope_plan_digest"),
                f"{repository}.scope_plan_digest",
            )
            if not DIGEST_PATTERN.fullmatch(scope_digest):
                raise IndexError(f"{repository}: invalid scope plan digest")
            _nonnegative_integer(
                record.get("scope_exclusions"), f"{repository}.scope_exclusions"
            )
    elif status == "scan_error":
        error_code = _string(record.get("error_code"), f"{repository}.error_code")
        if not ERROR_CODE_PATTERN.fullmatch(error_code):
            raise IndexError(f"{repository}: invalid failure class")
        project["non_completion_class"] = error_code
    else:
        raise IndexError(f"{repository}: unsupported analysis status")
    return project


def build_index(
    summary_content: bytes,
    manifest_content: bytes,
) -> dict[str, object]:
    summary = _load_json_object(summary_content)
    _validate_no_evidence_payload(summary)
    manifest = _load_manifest(manifest_content)
    corpus = summary.get("corpus")
    if not isinstance(corpus, list) or not all(
        isinstance(record, dict) for record in corpus
    ):
        raise IndexError("summary.corpus must be an array of objects")
    by_repository: dict[str, dict[str, object]] = {}
    for record in corpus:
        repository = record.get("repository")
        if not isinstance(repository, str) or repository in by_repository:
            raise IndexError("summary has an invalid or duplicate repository")
        by_repository[repository] = record
    manifest_names = {record["repository"] for record in manifest}
    if set(by_repository) != manifest_names:
        raise IndexError("summary and manifest repository sets differ")

    projects = [
        _project(record, by_repository[record["repository"]])
        for record in manifest
    ]
    completed = sum(
        project["analysis_status"] == "completed" for project in projects
    )
    return {
        "schema_version": "1.0",
        "document_type": "pgextassure.public-assurance-index",
        "latest_source_revision_date": max(
            record["commit_date"] for record in manifest
        ),
        "notice": {
            "purpose": (
                "Reproducible public inventory of static-analysis coverage "
                "for pinned PostgreSQL extension revisions."
            ),
            "not_a_security_rating": True,
            "not_a_certification": True,
            "no_vulnerability_disclosure": True,
            "limitations": [
                "A completed analysis is not a claim that a project is safe.",
                "Static analysis does not establish runtime behavior.",
                "Capability profiles describe observed functionality, not vulnerabilities.",
                "Finding, severity, rule, evidence, path, and source details are omitted.",
            ],
        },
        "provenance": {
            "normalized_summary_digest": _sha256(summary_content),
            "manifest_digest": _sha256(manifest_content),
            "tool": _tool(summary),
        },
        "summary": {
            "projects": len(projects),
            "analyses_completed": completed,
            "analyses_not_completed": len(projects) - completed,
        },
        "projects": projects,
    }


def render_json(document: Mapping[str, object]) -> str:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


def render_markdown(document: Mapping[str, object]) -> str:
    summary = document["summary"]
    provenance = document["provenance"]
    tool = provenance["tool"]
    lines = [
        "# PgExtAssure Extension Assurance Index",
        "",
        (
            "This is a reproducible inventory of static-analysis coverage for "
            "pinned public PostgreSQL extension revisions. It is **not a security "
            "rating, certification, vulnerability report, or allowlist decision**."
        ),
        "",
        (
            f"Snapshot: {summary['projects']} projects; "
            f"{summary['analyses_completed']} analyses completed; "
            f"{summary['analyses_not_completed']} not completed. Latest pinned "
            f"source revision date: {document['latest_source_revision_date']}."
        ),
        "",
        (
            f"Generated from PgExtAssure {tool['version']} with ruleset "
            f"{tool['ruleset_version']}."
        ),
        "",
        "| Project | Pinned revision | Analysis | Files | Capability profile | Controls |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for project in document["projects"]:
        link = f"[{project['name']}]({project['repository_url']})"
        revision = project["revision"][:12]
        status = (
            "completed"
            if project["analysis_status"] == "completed"
            else "not completed"
        )
        files = str(project.get("files_analyzed", "—"))
        capabilities = ", ".join(project.get("capability_profile", ())) or "none observed"
        controls = project["coverage_controls"]
        control_labels = []
        if controls["generation_plan_used"]:
            control_labels.append("generation plan")
        if controls["scope_plan_used"]:
            control_labels.append("scope plan")
        control_text = ", ".join(control_labels) or "default scan scope"
        lines.append(
            f"| {link} | `{revision}` | {status} | {files} | "
            f"{capabilities} | {control_text} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "A completed row means the pinned source was processed successfully. It does not constitute a security review. Capability profiles describe observed functionality and must not be interpreted as vulnerabilities. Finding counts, severities, rule identifiers, evidence, paths, and source excerpts are intentionally excluded.",
            "",
            "Input integrity:",
            "",
            f"- normalized summary: `{provenance['normalized_summary_digest']}`",
            f"- pinned manifest: `{provenance['manifest_digest']}`",
            "",
        ]
    )
    return "\n".join(lines)


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise IndexError(f"refusing symlink output path: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def generate(summary: Path, manifest: Path, output_dir: Path) -> None:
    summary_content = _read_bytes(summary, "normalized summary")
    manifest_content = _read_bytes(manifest, "manifest")
    document = build_index(summary_content, manifest_content)
    _atomic_write(output_dir / "index.json", render_json(document))
    _atomic_write(output_dir / "index.md", render_markdown(document))


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        generate(arguments.summary, arguments.manifest, arguments.output_dir)
    except (IndexError, OSError) as error:
        print(f"pgextassure assurance index: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
