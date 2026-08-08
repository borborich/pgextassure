#!/usr/bin/env python3
"""Verify the disclosure-safe external reproduction protocol and write its report."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path


EXPECTED = {
    "evidence_sha256": "e4a7b2e46591ca0519345664a77c203bcced7532cf2733dbe372376e10c53790",
    "manifest_digest": "sha256:02387036eb48fcdd9ec40c56bdf30702f3fc669b1bb013a2d13f68214dacb789",
    "coverage_digest": "sha256:3d34eacb093cbd114c15b75571660a52afa85c2f70dc8b57bf64fa66065156dd",
    "tool_version": "0.1.0-alpha.16",
    "ruleset_version": "2026-08-07.2",
    "postgres_version": "16.13",
}

RUNTIME_MARKERS = {
    "security-definer-shadowing": (
        "EXTERNAL_REPRODUCTION|security-definer-shadowing|PASS"
    ),
    "security-definer-trigger": (
        "EXTERNAL_REPRODUCTION|security-definer-trigger|PASS"
    ),
}


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"


def _regular_file(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular, non-symlink file")
    return path


def _load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _require_equal(observed: object, expected: object, label: str) -> None:
    if observed != expected:
        raise ValueError(f"{label}: expected {expected!r}, observed {observed!r}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--predicate", required=True)
    parser.add_argument("--sbom", required=True)
    parser.add_argument("--shadowing-output", required=True)
    parser.add_argument("--trigger-output", required=True)
    parser.add_argument("--postgres-version-output", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-revision", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    evidence = _regular_file(args.evidence, "evidence")
    predicate_path = _regular_file(args.predicate, "predicate")
    sbom = _regular_file(args.sbom, "SBOM")
    shadowing = _regular_file(args.shadowing_output, "shadowing output")
    trigger = _regular_file(args.trigger_output, "trigger output")
    postgres_version_path = _regular_file(
        args.postgres_version_output, "PostgreSQL version output"
    )
    output = Path(args.output)

    predicate = _load_json(predicate_path)
    if not isinstance(predicate, dict):
        raise ValueError("predicate must be a JSON object")

    tool = predicate.get("tool")
    subject = predicate.get("subject")
    result = predicate.get("result")
    if not isinstance(tool, dict) or not isinstance(subject, dict) or not isinstance(result, dict):
        raise ValueError("predicate is missing tool, subject, or result metadata")

    _require_equal(tool.get("name"), "pgextassure", "tool name")
    _require_equal(tool.get("version"), EXPECTED["tool_version"], "tool version")
    _require_equal(
        tool.get("ruleset_version"), EXPECTED["ruleset_version"], "ruleset version"
    )
    _require_equal(
        subject.get("manifest_digest"), EXPECTED["manifest_digest"], "manifest digest"
    )
    _require_equal(
        subject.get("coverage_digest"), EXPECTED["coverage_digest"], "coverage digest"
    )
    _require_equal(result.get("gate"), "pass", "fixture gate")
    _require_equal(result.get("fail_on"), "none", "fixture fail-on")

    evidence_digest = _digest(evidence)
    _require_equal(
        evidence_digest,
        f"sha256:{EXPECTED['evidence_sha256']}",
        "deterministic evidence digest",
    )

    runtime_files = {
        "security-definer-shadowing": shadowing,
        "security-definer-trigger": trigger,
    }
    checks = [
        {
            "id": "scanner-evidence",
            "status": "pass",
            "expected_digest": f"sha256:{EXPECTED['evidence_sha256']}",
            "observed_digest": evidence_digest,
        }
    ]
    for check_id, path in runtime_files.items():
        text = path.read_text(encoding="utf-8")
        marker = RUNTIME_MARKERS[check_id]
        if marker not in text:
            raise ValueError(f"{check_id}: success marker not found")
        checks.append(
            {
                "id": check_id,
                "status": "pass",
                "output_digest": _digest(path),
            }
        )

    postgres_version = postgres_version_path.read_text(encoding="utf-8").strip()
    if EXPECTED["postgres_version"] not in postgres_version:
        raise ValueError(
            "PostgreSQL version: expected output containing "
            f"{EXPECTED['postgres_version']!r}, observed {postgres_version!r}"
        )

    report = {
        "report_type": "pgextassure.external-reproduction",
        "schema_version": "1.0",
        "outcome": "pass",
        "scope": "controlled-fixture-and-postgresql-semantics",
        "operator": {
            "github_actor": args.actor,
            "repository": args.repository,
            "run_url": args.run_url,
            "workflow_revision": args.workflow_revision,
        },
        "tool": {
            "commit": "96e0f14fe8f2f86a11be1341f87ddece9385a8b2",
            "name": "pgextassure",
            "ruleset_version": EXPECTED["ruleset_version"],
            "version": EXPECTED["tool_version"],
        },
        "environment": {
            "postgres_image": (
                "postgres:16.13-bookworm@sha256:"
                "472efd9a66f2b2f1a5aeb18b28de74332e6ef88c2b93a1a5d812fb6db67a5f60"
            ),
            "postgres_version": postgres_version,
            "python_version": platform.python_version(),
            "runner_arch": args.runner_arch,
            "runner_os": args.runner_os,
        },
        "checks": checks,
        "artifacts": {
            "evidence": evidence_digest,
            "predicate": _digest(predicate_path),
            "sbom": _digest(sbom),
        },
        "limitations": [
            "This reproduces a controlled fixture and two PostgreSQL semantics.",
            "It is not a security certification or an extension allowlist decision.",
            "Independence is adjudicated from the operator identity and run provenance.",
        ],
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"external reproduction: PASS ({output})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
