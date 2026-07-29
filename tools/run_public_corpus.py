#!/usr/bin/env python3
"""Run PgExtAssure against pinned, already-checked-out public repositories."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import dataclass
from datetime import date
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from typing import Sequence

from pgextassure.generation import (
    GenerationPlan,
    GenerationPlanError,
    load_generation_plan,
)
from pgextassure.grouping import group_findings
from pgextassure.reporting import render_json
from pgextassure.scanner import (
    RULESET_VERSION,
    TOOL_VERSION,
    ScanError,
    ScanInputError,
    scan_path,
)
from pgextassure.scope import ScopePlan, ScopePlanError, load_scope_plan


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "benchmarks" / "public-corpus" / "manifest.tsv"
)
DEFAULT_OUTPUT = PROJECT_ROOT / "benchmark-results" / "public-corpus"
MANIFEST_REQUIRED_FIELDS = (
    "repository",
    "url",
    "commit",
    "commit_date",
    "scan_path",
)
MANIFEST_FIELDS = (
    *MANIFEST_REQUIRED_FIELDS,
    "generation_plan",
    "scope_plan",
)
MANIFEST_HEADERS = {
    MANIFEST_REQUIRED_FIELDS,
    (*MANIFEST_REQUIRED_FIELDS, "generation_plan"),
    (*MANIFEST_REQUIRED_FIELDS, "scope_plan"),
    MANIFEST_FIELDS,
}
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
GITHUB_URL_PATTERN = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git\Z"
)


class CorpusError(RuntimeError):
    """The corpus manifest or checkout set is not reproducible."""


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    repository: str
    url: str
    commit: str
    commit_date: str
    scan_path: str
    generation_plan: str
    scope_plan: str


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan pinned local public-extension checkouts without executing "
            "their code."
        )
    )
    parser.add_argument(
        "corpus_root",
        type=Path,
        help="directory containing one checkout per manifest repository",
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
        help="directory for normalized summary.json and summary.tsv",
    )
    parser.add_argument(
        "--raw-report-dir",
        type=Path,
        help=(
            "explicit opt-in directory for full evidence-bearing JSON reports; "
            "keep this outside the public repository until adjudicated"
        ),
    )
    return parser.parse_args(argv)


def _validate_scan_path(value: str, *, row_number: int) -> str:
    if not value or "\\" in value:
        raise CorpusError(
            f"manifest row {row_number}: scan_path must be a POSIX relative path"
        )
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise CorpusError(
            f"manifest row {row_number}: scan_path must stay inside checkout"
        )
    return path.as_posix() if path.parts else "."


def load_manifest(path: Path) -> tuple[CorpusEntry, ...]:
    try:
        handle = path.open(encoding="utf-8", newline="")
    except OSError as error:
        raise CorpusError(f"cannot open manifest {path}: {error}") from error

    with handle:
        reader = csv.DictReader(handle, delimiter="\t")
        header = tuple(reader.fieldnames or ())
        if header not in MANIFEST_HEADERS:
            raise CorpusError(
                "manifest header must be exactly: "
                + "\t".join(MANIFEST_REQUIRED_FIELDS)
                + " with optional generation_plan and scope_plan columns"
            )
        entries: list[CorpusEntry] = []
        seen: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            repository = row["repository"]
            url = row["url"]
            commit = row["commit"]
            commit_date = row["commit_date"]
            if not REPOSITORY_PATTERN.fullmatch(repository):
                raise CorpusError(
                    f"manifest row {row_number}: invalid repository name"
                )
            if repository in seen:
                raise CorpusError(
                    f"manifest row {row_number}: duplicate repository "
                    f"{repository!r}"
                )
            if not GITHUB_URL_PATTERN.fullmatch(url):
                raise CorpusError(
                    f"manifest row {row_number}: URL must be an HTTPS GitHub "
                    "clone URL"
                )
            if not COMMIT_PATTERN.fullmatch(commit):
                raise CorpusError(
                    f"manifest row {row_number}: commit must be 40 lowercase "
                    "hexadecimal characters"
                )
            try:
                date.fromisoformat(commit_date)
            except ValueError as error:
                raise CorpusError(
                    f"manifest row {row_number}: invalid commit_date"
                ) from error
            scan_target = _validate_scan_path(
                row["scan_path"],
                row_number=row_number,
            )
            generation_plan = row.get("generation_plan") or "-"
            if generation_plan != "-":
                generation_plan = _validate_scan_path(
                    generation_plan,
                    row_number=row_number,
                )
                if generation_plan == ".":
                    raise CorpusError(
                        f"manifest row {row_number}: generation_plan must name a file"
                    )
            scope_plan = row.get("scope_plan") or "-"
            if scope_plan != "-":
                scope_plan = _validate_scan_path(
                    scope_plan,
                    row_number=row_number,
                )
                if scope_plan == ".":
                    raise CorpusError(
                        f"manifest row {row_number}: scope_plan must name a file"
                    )
            seen.add(repository)
            entries.append(
                CorpusEntry(
                    repository=repository,
                    url=url,
                    commit=commit,
                    commit_date=commit_date,
                    scan_path=scan_target,
                    generation_plan=generation_plan,
                    scope_plan=scope_plan,
                )
            )
    if not entries:
        raise CorpusError("manifest contains no repositories")
    return tuple(entries)


def _git_head(checkout: Path) -> str:
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(checkout),
                "rev-parse",
                "--verify",
                "HEAD^{commit}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CorpusError(f"{checkout.name}: cannot inspect Git HEAD") from error
    if result.returncode != 0:
        raise CorpusError(f"{checkout.name}: Git HEAD is unavailable")
    return result.stdout.strip()


def _validated_targets(
    corpus_root: Path,
    entries: Sequence[CorpusEntry],
) -> tuple[tuple[CorpusEntry, Path], ...]:
    if corpus_root.is_symlink():
        raise CorpusError("corpus root must not be a symlink")
    try:
        resolved_root = corpus_root.resolve(strict=True)
    except OSError as error:
        raise CorpusError(f"cannot resolve corpus root {corpus_root}") from error
    if not resolved_root.is_dir():
        raise CorpusError(f"corpus root is not a directory: {corpus_root}")

    targets: list[tuple[CorpusEntry, Path]] = []
    for entry in entries:
        checkout = resolved_root / entry.repository
        if checkout.is_symlink() or not checkout.is_dir():
            raise CorpusError(
                f"{entry.repository}: checkout is missing or is a symlink"
            )
        actual_commit = _git_head(checkout)
        if actual_commit != entry.commit:
            raise CorpusError(
                f"{entry.repository}: expected {entry.commit}, "
                f"found {actual_commit}"
            )
        target = (
            checkout
            if entry.scan_path == "."
            else checkout.joinpath(*PurePosixPath(entry.scan_path).parts)
        )
        try:
            target.resolve(strict=True).relative_to(checkout.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise CorpusError(
                f"{entry.repository}: scan_path is missing or escapes checkout"
            ) from error
        targets.append((entry, target))
    return tuple(targets)


def _generation_plans(
    manifest: Path,
    entries: Sequence[CorpusEntry],
) -> dict[str, GenerationPlan]:
    plans: dict[str, GenerationPlan] = {}
    root = manifest.resolve().parent
    for entry in entries:
        if entry.generation_plan == "-":
            continue
        candidate = root.joinpath(
            *PurePosixPath(entry.generation_plan).parts
        )
        try:
            candidate.resolve(strict=True).relative_to(root)
            plans[entry.repository] = load_generation_plan(candidate)
        except (GenerationPlanError, OSError, ValueError) as error:
            raise CorpusError(
                f"{entry.repository}: invalid generation plan: {error}"
            ) from error
    return plans


def _scope_plans(
    manifest: Path,
    entries: Sequence[CorpusEntry],
) -> dict[str, ScopePlan]:
    plans: dict[str, ScopePlan] = {}
    root = manifest.resolve().parent
    for entry in entries:
        if entry.scope_plan == "-":
            continue
        candidate = root.joinpath(*PurePosixPath(entry.scope_plan).parts)
        try:
            candidate.resolve(strict=True).relative_to(root)
            plans[entry.repository] = load_scope_plan(candidate)
        except (ScopePlanError, OSError, ValueError) as error:
            raise CorpusError(
                f"{entry.repository}: invalid scope plan: {error}"
            ) from error
    return plans


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise CorpusError(f"refusing symlink output path: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="",
        ) as handle:
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


def _normalized_record(
    entry: CorpusEntry,
    report,
) -> dict[str, object]:
    rule_counts = Counter(finding.rule_id for finding in report.findings)
    groups = group_findings(report.findings)
    root_cause_rule_counts = Counter(group.rule_id for group in groups)
    root_cause_severity_counts = Counter(
        group.severity.value for group in groups
    )
    record = {
        "repository": entry.repository,
        "url": entry.url,
        "commit": entry.commit,
        "commit_date": entry.commit_date,
        "scan_path": entry.scan_path,
        "generation_plan": entry.generation_plan,
        "scope_plan": entry.scope_plan,
        "status": "ok",
        "source_manifest_digest": report.manifest.digest,
        "files_scanned": report.summary.files_scanned,
        "findings": report.summary.findings,
        "root_causes": len(groups),
        "generated_artifacts": 0,
        "by_severity": dict(report.summary.by_severity),
        "root_causes_by_severity": {
            severity: root_cause_severity_counts[severity]
            for severity in ("critical", "high", "medium", "low")
        },
        "capabilities": list(report.summary.capabilities),
        "rule_counts": dict(sorted(rule_counts.items())),
        "root_cause_rule_counts": dict(
            sorted(root_cause_rule_counts.items())
        ),
    }
    if report.generation is not None:
        record["generation_plan_digest"] = report.generation["plan"]["digest"]
        record["generated_artifacts"] = len(report.generation["artifacts"])
    if report.scope is not None:
        record["scope_plan_digest"] = report.scope["plan"]["digest"]
        record["scope_exclusions"] = len(report.scope["exclusions"])
    return record


def _error_record(
    entry: CorpusEntry,
    error: ScanError,
) -> dict[str, object]:
    return {
        "repository": entry.repository,
        "url": entry.url,
        "commit": entry.commit,
        "commit_date": entry.commit_date,
        "scan_path": entry.scan_path,
        "generation_plan": entry.generation_plan,
        "scope_plan": entry.scope_plan,
        "status": "scan_error",
        "error_type": type(error).__name__,
        "error_code": _scan_error_code(error),
    }


def _scan_error_code(error: ScanError) -> str:
    """Return a stable, non-evidence-bearing class for a scan failure."""

    message = str(error)
    if isinstance(error, ScanInputError):
        categories = (
            ("refusing symlinked directory in scan tree", "symlinked_directory"),
            ("refusing symlinked supported source file", "symlinked_source"),
            ("refusing symlink scan root", "symlinked_root"),
            ("no supported source files found", "no_supported_source"),
            ("not valid UTF-8", "invalid_encoding"),
            ("not UTF-8", "invalid_encoding"),
            ("binary data found", "invalid_encoding"),
            ("limit", "resource_limit"),
            ("exceeds", "resource_limit"),
        )
        for marker, code in categories:
            if marker in message:
                return code
        return "invalid_input"
    return "scan_failure"


def _summary_tsv(records: Sequence[dict[str, object]]) -> str:
    columns = (
        "repository",
        "commit",
        "status",
        "error_code",
        "files",
        "findings",
        "root_causes",
        "generated_artifacts",
        "finding_critical",
        "finding_high",
        "finding_medium",
        "finding_low",
        "root_cause_critical",
        "root_cause_high",
        "root_cause_medium",
        "root_cause_low",
    )
    lines = ["\t".join(columns)]
    for record in records:
        severity = record.get("by_severity")
        counts = severity if isinstance(severity, dict) else {}
        root_cause_severity = record.get("root_causes_by_severity")
        root_cause_counts = (
            root_cause_severity
            if isinstance(root_cause_severity, dict)
            else {}
        )
        lines.append(
            "\t".join(
                (
                    str(record["repository"]),
                    str(record["commit"]),
                    str(record["status"]),
                    str(record.get("error_code", "")),
                    str(record.get("files_scanned", "")),
                    str(record.get("findings", "")),
                    str(record.get("root_causes", "")),
                    str(record.get("generated_artifacts", "")),
                    str(counts.get("critical", "")),
                    str(counts.get("high", "")),
                    str(counts.get("medium", "")),
                    str(counts.get("low", "")),
                    str(root_cause_counts.get("critical", "")),
                    str(root_cause_counts.get("high", "")),
                    str(root_cause_counts.get("medium", "")),
                    str(root_cause_counts.get("low", "")),
                )
            )
        )
    return "\n".join(lines) + "\n"


def run_corpus(
    corpus_root: Path,
    manifest: Path,
    output_dir: Path,
    *,
    raw_report_dir: Path | None = None,
) -> int:
    entries = load_manifest(manifest)
    targets = _validated_targets(corpus_root, entries)
    generation_plans = _generation_plans(manifest, entries)
    scope_plans = _scope_plans(manifest, entries)
    records: list[dict[str, object]] = []
    had_scan_error = False

    if raw_report_dir is not None:
        print(
            "warning: raw reports contain evidence and must be reviewed before "
            "publication",
            file=sys.stderr,
        )

    for entry, target in targets:
        try:
            report = scan_path(
                target,
                generation_plan=generation_plans.get(entry.repository),
                scope_plan=scope_plans.get(entry.repository),
            )
        except ScanError as error:
            had_scan_error = True
            records.append(_error_record(entry, error))
            continue
        records.append(_normalized_record(entry, report))
        if raw_report_dir is not None:
            _atomic_write(
                raw_report_dir / f"{entry.repository}.json",
                render_json(report),
            )

    document = {
        "schema_version": "1.0",
        "tool": {
            "name": "pgextassure",
            "version": TOOL_VERSION,
            "ruleset_version": RULESET_VERSION,
        },
        "corpus": records,
    }
    rendered_json = (
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    rendered_tsv = _summary_tsv(records)
    _atomic_write(output_dir / "summary.json", rendered_json)
    _atomic_write(output_dir / "summary.tsv", rendered_tsv)
    sys.stdout.write(rendered_tsv)
    return 1 if had_scan_error else 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        return run_corpus(
            arguments.corpus_root,
            arguments.manifest,
            arguments.output_dir,
            raw_report_dir=arguments.raw_report_dir,
        )
    except (CorpusError, OSError) as error:
        print(f"pgextassure corpus: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
