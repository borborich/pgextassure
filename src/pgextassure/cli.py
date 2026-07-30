"""Command-line interface for PgExtAssure."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Sequence

from .admission import (
    AdmissionError,
    apply_admission,
    gate_root_causes,
    load_baseline,
    load_suppressions,
    parse_admission_date,
    render_baseline,
)
from .evidence import (
    BUNDLE_SCHEMA_VERSION,
    EvidenceError,
    create_evidence_bundle,
    expected_material_digests,
    read_evidence_material,
    verify_evidence_bundle,
)
from .enterprise import AdmissionEnforcementError, enforce_pilot_package
from .generation import GenerationPlanError, load_generation_plan
from .gateway import (
    GatewayConfig,
    GatewayError,
    create_gateway_server,
    is_loopback_host,
)
from .integrations import (
    INTEGRATION_PROFILES,
    AdmissionEventError,
    IntegrationError,
    project_admission_event,
)
from .models import SEVERITY_RANK, ScanReport, Severity
from .pilot import (
    PilotPackageError,
    create_pilot_package,
    verify_pilot_package,
)
from .policy import (
    POLICY_TEMPLATE_PROFILES,
    PolicyError,
    apply_policy,
    load_policy,
    render_policy_template,
)
from .reporting import (
    render_grouped_json,
    render_github_annotations,
    render_json,
    render_sarif,
    render_text,
    sanitize_terminal_text,
)
from .review import (
    ReviewError,
    render_decision_template,
    render_review_pack,
    verify_decision_ledger,
)
from .scanner import TOOL_VERSION, ScanError, ScanInputError, scan_path
from .signing import (
    SigningError,
    sign_evidence_bundle,
    verify_evidence_signature,
)
from .scope import ScopePlanError, load_scope_plan
from .trust import (
    TrustPolicyError,
    TrustVerificationError,
    evaluate_admission,
    verify_admission_receipt,
)


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_SCAN_ERROR = 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pgextassure",
        description="Statically assess PostgreSQL extension packages.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOL_VERSION}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan = subcommands.add_parser(
        "scan", help="scan a file or directory without executing code"
    )
    scan.add_argument("path", metavar="PATH")
    scan.add_argument(
        "--format",
        choices=("text", "json", "grouped-json", "review-json", "sarif"),
        default="text",
        dest="output_format",
    )
    scan.add_argument("--output", metavar="FILE")
    scan.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "none"),
        default="none",
    )
    scan.add_argument(
        "--generation-plan",
        metavar="FILE",
        help=(
            "strict JSON declaration for pinned build-generated SQL/control "
            "artifacts; templates are rendered in memory without executing a build"
        ),
    )
    scan.add_argument(
        "--scope-plan",
        metavar="FILE",
        help=(
            "strict digest-bound JSON declaration for scan roots and exact "
            "filesystem exclusions"
        ),
    )
    scan.add_argument(
        "--baseline",
        metavar="FILE",
        help="strict root-cause baseline created by the baseline subcommand",
    )
    scan.add_argument(
        "--suppressions",
        metavar="FILE",
        help=(
            "strict owner-attributed root-cause suppressions with expiry dates"
        ),
    )
    scan.add_argument(
        "--evaluated-on",
        metavar="YYYY-MM-DD",
        help=(
            "explicit suppression evaluation date; defaults to the current "
            "UTC date when suppressions are supplied"
        ),
    )
    scan.add_argument(
        "--policy",
        metavar="FILE",
        help=(
            "strict organization policy that owns the gate and constrains "
            "baseline and suppression use"
        ),
    )
    scan.add_argument(
        "--github-annotations",
        choices=("none", "active", "all"),
        default="none",
        help=(
            "emit bounded root-cause workflow annotations to stdout; "
            "requires --output"
        ),
    )
    scan.add_argument(
        "--max-annotations",
        type=int,
        choices=range(2, 51),
        default=25,
        metavar="2..50",
        help="maximum workflow-command lines, including truncation notice",
    )

    baseline = subcommands.add_parser(
        "baseline",
        help="create a root-cause baseline without suppressing report evidence",
    )
    baseline.add_argument("path", metavar="PATH")
    baseline.add_argument("--output", metavar="FILE")
    baseline.add_argument(
        "--created-on",
        metavar="YYYY-MM-DD",
        help="baseline creation date; defaults to the current UTC date",
    )
    baseline.add_argument(
        "--generation-plan",
        metavar="FILE",
        help=(
            "strict JSON declaration for pinned build-generated SQL/control "
            "artifacts; templates are rendered in memory without executing a build"
        ),
    )
    baseline.add_argument("--scope-plan", metavar="FILE")
    policy_template = subcommands.add_parser(
        "policy-template",
        help="write a packaged organization policy template for review",
    )
    policy_template.add_argument(
        "profile",
        choices=POLICY_TEMPLATE_PROFILES,
    )
    policy_template.add_argument("--output", metavar="FILE")
    review = subcommands.add_parser(
        "review",
        help="create and verify authority-free agent review decisions",
    )
    review_commands = review.add_subparsers(
        dest="review_command",
        required=True,
    )
    review_template = review_commands.add_parser(
        "template",
        help="create an unresolved decision ledger from a review pack",
    )
    review_template.add_argument("path", metavar="REVIEW_PACK")
    review_template.add_argument("--output", metavar="FILE", required=True)
    review_verify = review_commands.add_parser(
        "verify",
        help="verify a decision ledger against its exact review pack",
    )
    review_verify.add_argument("path", metavar="REVIEW_PACK")
    review_verify.add_argument("ledger", metavar="DECISION_LEDGER")
    review_verify.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
    )
    evidence = subcommands.add_parser(
        "evidence",
        help="create or independently verify a bounded evidence bundle",
    )
    evidence_commands = evidence.add_subparsers(
        dest="evidence_command",
        required=True,
    )
    evidence_create = evidence_commands.add_parser(
        "create",
        help="scan an extension and create a deterministic evidence bundle",
    )
    evidence_create.add_argument("path", metavar="PATH")
    evidence_create.add_argument("--output", metavar="FILE", required=True)
    evidence_create.add_argument(
        "--created-on",
        metavar="YYYY-MM-DD",
        help="bundle date; defaults to the current UTC date",
    )
    evidence_create.add_argument(
        "--component-name",
        default="postgresql-extension",
        help="non-secret component name for the SPDX inventory",
    )
    evidence_create.add_argument(
        "--component-version",
        help="optional component version for the SPDX inventory",
    )
    evidence_create.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "none"),
        default="none",
    )
    evidence_create.add_argument("--generation-plan", metavar="FILE")
    evidence_create.add_argument("--scope-plan", metavar="FILE")
    evidence_create.add_argument("--baseline", metavar="FILE")
    evidence_create.add_argument("--suppressions", metavar="FILE")
    evidence_create.add_argument("--evaluated-on", metavar="YYYY-MM-DD")
    evidence_create.add_argument("--policy", metavar="FILE")
    evidence_verify = evidence_commands.add_parser(
        "verify",
        help="verify a bundle offline without extracting it",
    )
    evidence_verify.add_argument("path", metavar="BUNDLE")
    evidence_verify.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
    )
    evidence_verify.add_argument(
        "--predicate-output",
        metavar="FILE",
        help=(
            "write the verified custom-attestation predicate to a separate file"
        ),
    )
    evidence_verify.add_argument(
        "--sbom-output",
        metavar="FILE",
        help="write the verified SPDX inventory to a separate file",
    )
    evidence_sign = evidence_commands.add_parser(
        "sign",
        help="sign a verified bundle with an offline corporate RSA key",
    )
    evidence_sign.add_argument("path", metavar="BUNDLE")
    evidence_sign.add_argument("--private-key", metavar="FILE", required=True)
    evidence_sign.add_argument("--signer-id", required=True)
    evidence_sign.add_argument(
        "--created-on",
        metavar="YYYY-MM-DD",
        help="signature date; defaults to the current UTC date",
    )
    evidence_sign.add_argument(
        "--passphrase-env",
        metavar="NAME",
        help="environment variable containing the private-key passphrase",
    )
    evidence_sign.add_argument("--openssl", metavar="FILE")
    evidence_sign.add_argument(
        "--statement-output",
        metavar="FILE",
        required=True,
    )
    evidence_sign.add_argument(
        "--signature-output",
        metavar="FILE",
        required=True,
    )
    evidence_sign.add_argument(
        "--public-key-output",
        metavar="FILE",
        required=True,
    )
    evidence_signature_verify = evidence_commands.add_parser(
        "verify-signature",
        help="verify a corporate signature and its Evidence Bundle offline",
    )
    evidence_signature_verify.add_argument("path", metavar="BUNDLE")
    evidence_signature_verify.add_argument(
        "--statement",
        metavar="FILE",
        required=True,
    )
    evidence_signature_verify.add_argument(
        "--signature",
        metavar="FILE",
        required=True,
    )
    evidence_signature_verify.add_argument(
        "--public-key",
        metavar="FILE",
        required=True,
    )
    evidence_signature_verify.add_argument(
        "--expected-key-sha256",
        metavar="sha256:DIGEST",
        help="trusted expected SHA-256 of the DER public key",
    )
    evidence_signature_verify.add_argument("--openssl", metavar="FILE")
    evidence_signature_verify.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
    )
    trust = subcommands.add_parser(
        "trust",
        help="evaluate signed evidence against an enterprise trust policy",
    )
    trust_commands = trust.add_subparsers(
        dest="trust_command",
        required=True,
    )
    trust_evaluate = trust_commands.add_parser(
        "evaluate",
        help="create a deterministic admission receipt",
    )
    trust_evaluate.add_argument("path", metavar="BUNDLE")
    trust_evaluate.add_argument("--statement", metavar="FILE", required=True)
    trust_evaluate.add_argument("--signature", metavar="FILE", required=True)
    trust_evaluate.add_argument("--public-key", metavar="FILE", required=True)
    trust_evaluate.add_argument(
        "--trust-policy",
        metavar="FILE",
        required=True,
    )
    trust_evaluate.add_argument(
        "--evaluated-on",
        metavar="YYYY-MM-DD",
        help="explicit evaluation date; defaults to the current UTC date",
    )
    trust_evaluate.add_argument("--request-id", required=True)
    trust_evaluate.add_argument("--target", required=True)
    trust_evaluate.add_argument("--openssl", metavar="FILE")
    trust_evaluate.add_argument("--output", metavar="FILE", required=True)
    trust_evaluate.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
    )
    trust_verify = trust_commands.add_parser(
        "verify-receipt",
        help="recompute a receipt and check whether admission remains active",
    )
    trust_verify.add_argument("path", metavar="RECEIPT")
    trust_verify.add_argument("--bundle", metavar="FILE", required=True)
    trust_verify.add_argument("--statement", metavar="FILE", required=True)
    trust_verify.add_argument("--signature", metavar="FILE", required=True)
    trust_verify.add_argument("--public-key", metavar="FILE", required=True)
    trust_verify.add_argument(
        "--trust-policy",
        metavar="FILE",
        required=True,
    )
    trust_verify.add_argument(
        "--expected-trust-policy-sha256",
        metavar="sha256:DIGEST",
    )
    trust_verify.add_argument("--expected-request-id", required=True)
    trust_verify.add_argument("--expected-target", required=True)
    trust_verify.add_argument(
        "--expected-evaluated-on",
        metavar="YYYY-MM-DD",
        required=True,
    )
    trust_verify.add_argument(
        "--verified-on",
        metavar="YYYY-MM-DD",
        help="receipt-use date; defaults to the current UTC date",
    )
    trust_verify.add_argument("--openssl", metavar="FILE")
    trust_verify.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
    )
    pilot = subcommands.add_parser(
        "pilot",
        help="create or verify a portable enterprise pilot handoff",
    )
    pilot_commands = pilot.add_subparsers(
        dest="pilot_command",
        required=True,
    )
    pilot_package = pilot_commands.add_parser(
        "package",
        help="create a deterministic pilot package from a staging directory",
    )
    pilot_package.add_argument("path", metavar="DIRECTORY")
    pilot_package.add_argument("--output", metavar="FILE", required=True)
    pilot_package.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
    )
    pilot_verify = pilot_commands.add_parser(
        "verify-package",
        help="verify a pilot package without extracting it",
    )
    pilot_verify.add_argument("path", metavar="PACKAGE")
    pilot_verify.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
    )
    pilot_enforce = pilot_commands.add_parser(
        "enforce",
        help="enforce an embedded admission receipt against external trust anchors",
    )
    pilot_enforce.add_argument("path", metavar="PACKAGE")
    pilot_enforce.add_argument(
        "--expected-package-sha256",
        metavar="sha256:DIGEST",
        required=True,
    )
    pilot_enforce.add_argument(
        "--expected-key-sha256",
        metavar="sha256:DIGEST",
        required=True,
    )
    pilot_enforce.add_argument(
        "--expected-trust-policy-sha256",
        metavar="sha256:DIGEST",
        required=True,
    )
    pilot_enforce.add_argument("--expected-request-id", required=True)
    pilot_enforce.add_argument("--expected-target", required=True)
    pilot_enforce.add_argument(
        "--expected-evaluated-on",
        metavar="YYYY-MM-DD",
        required=True,
    )
    pilot_enforce.add_argument(
        "--verified-on",
        metavar="YYYY-MM-DD",
        help="receipt-use date; defaults to the current UTC date",
    )
    pilot_enforce.add_argument("--openssl", metavar="FILE")
    pilot_enforce.add_argument(
        "--event-output",
        metavar="FILE",
        help="write the canonical Admission Event 1.0 JSON",
    )
    pilot_enforce.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
    )
    integration = subcommands.add_parser(
        "integration",
        help="project a verified Admission Event into a vendor API payload",
    )
    integration_commands = integration.add_subparsers(
        dest="integration_command",
        required=True,
    )
    integration_export = integration_commands.add_parser(
        "export",
        help="render a credential-free Jira, ServiceNow, Splunk, or Elastic payload",
    )
    integration_export.add_argument("path", metavar="ADMISSION_EVENT")
    integration_export.add_argument(
        "--profile",
        choices=INTEGRATION_PROFILES,
        required=True,
    )
    integration_export.add_argument(
        "--output",
        metavar="FILE",
        help="write the payload instead of stdout",
    )
    integration_export.add_argument(
        "--manifest-output",
        metavar="FILE",
        help="write the canonical Integration Export Manifest 1.0",
    )
    integration_export.add_argument(
        "--project",
        help="Jira project key",
    )
    integration_export.add_argument(
        "--issue-type",
        default="Task",
        help="Jira issue type name",
    )
    integration_export.add_argument(
        "--table",
        default="change_request",
        help="ServiceNow Table API table",
    )
    integration_export.add_argument(
        "--index",
        help="Splunk or Elastic destination index",
    )
    gateway = subcommands.add_parser(
        "gateway",
        help="run the loopback-first enterprise admission HTTP gateway",
    )
    gateway_commands = gateway.add_subparsers(
        dest="gateway_command",
        required=True,
    )
    gateway_serve = gateway_commands.add_parser(
        "serve",
        help="serve health, readiness, and admission endpoints",
    )
    gateway_serve.add_argument("--host", default="127.0.0.1")
    gateway_serve.add_argument("--port", type=int, default=8080)
    gateway_ledger = gateway_serve.add_mutually_exclusive_group(required=True)
    gateway_ledger.add_argument(
        "--ledger",
        metavar="FILE",
        help="use a private local SQLite ledger",
    )
    gateway_ledger.add_argument(
        "--postgres-dsn-file",
        metavar="FILE",
        help="use PostgreSQL via a mode-0600 DSN secret file",
    )
    gateway_serve.add_argument(
        "--initialize-postgres-ledger",
        action="store_true",
        help="bootstrap schema 1 before serving; requires PostgreSQL DDL rights",
    )
    gateway_serve.add_argument(
        "--maximum-request-bytes",
        type=int,
        default=256 * 1024 * 1024,
    )
    gateway_serve.add_argument(
        "--maximum-concurrent-requests",
        type=int,
        default=4,
    )
    gateway_serve.add_argument(
        "--request-timeout-seconds",
        type=int,
        default=30,
    )
    gateway_serve.add_argument("--openssl", metavar="FILE")
    gateway_serve.add_argument(
        "--allow-remote",
        action="store_true",
        help="explicitly permit a non-loopback bind; deploy behind mTLS/auth",
    )
    return parser


def _render(
    report: ScanReport,
    output_format: str,
    *,
    sarif_path_prefix: str = "",
) -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "grouped-json":
        return render_grouped_json(report)
    if output_format == "review-json":
        return render_review_pack(report)
    if output_format == "sarif":
        return render_sarif(report, path_prefix=sarif_path_prefix)
    return render_text(report)


def _sarif_path_prefix(scan_input: str) -> str:
    """Map finding paths to repository-root-relative SARIF artifact URIs."""

    requested = Path(scan_input).resolve()
    scan_root = requested.parent if requested.is_file() else requested
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd())).resolve()
    try:
        relative = scan_root.relative_to(workspace)
    except ValueError:
        return ""
    return "" if relative == Path(".") else relative.as_posix()


def _threshold_reached(report: ScanReport, threshold: str) -> bool:
    if threshold == "none":
        return False
    minimum = SEVERITY_RANK[Severity(threshold)]
    if report.admission is not None:
        return bool(
            gate_root_causes(
                report,
                minimum_severity=Severity(threshold),
            )
        )
    return any(
        SEVERITY_RANK[finding.severity] >= minimum for finding in report.findings
    )


def _write_binary_output(path: str, rendered: bytes) -> None:
    """Atomically replace an output file without following its final symlink."""

    target = Path(path)
    absolute_target = Path(os.path.abspath(target))
    anchors = [Path.cwd()]
    workspace_value = os.environ.get("GITHUB_WORKSPACE")
    if workspace_value:
        anchors.append(Path(os.path.abspath(workspace_value)))
    scoped: list[tuple[int, Path, Path]] = []
    for anchor in anchors:
        try:
            relative = absolute_target.relative_to(anchor)
        except ValueError:
            continue
        scoped.append((len(anchor.parts), anchor, relative))
    if scoped:
        _, anchor, relative = max(scoped, key=lambda item: item[0])
        current = anchor
        for component in relative.parts[:-1]:
            current /= component
            if current.is_symlink():
                raise OSError(
                    f"refusing symlinked output directory: {current}"
                )
            if not current.exists():
                break

    parent = target.parent
    if target.is_symlink():
        raise OSError(f"refusing symlink output path: {target}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        dir=parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _write_output(path: str, rendered: str) -> None:
    _write_binary_output(path, rendered.encode("utf-8"))


def _controlled_scan(arguments: argparse.Namespace) -> ScanReport:
    generation_plan = (
        load_generation_plan(arguments.generation_plan)
        if arguments.generation_plan
        else None
    )
    scope_plan = (
        load_scope_plan(arguments.scope_plan)
        if arguments.scope_plan
        else None
    )
    report = scan_path(
        arguments.path,
        generation_plan=generation_plan,
        scope_plan=scope_plan,
    )
    policy = load_policy(arguments.policy) if arguments.policy else None
    if policy is not None and arguments.fail_on != "none":
        raise PolicyError(
            "--policy cannot be combined with --fail-on; "
            "the policy owns the gate"
        )
    baseline = (
        load_baseline(arguments.baseline) if arguments.baseline else None
    )
    suppressions = (
        load_suppressions(arguments.suppressions)
        if arguments.suppressions
        else None
    )
    if arguments.evaluated_on and suppressions is None:
        raise AdmissionError("--evaluated-on requires --suppressions")
    evaluated_on = (
        parse_admission_date(
            arguments.evaluated_on,
            label="suppression evaluation date",
        )
        if arguments.evaluated_on
        else (
            datetime.now(timezone.utc).date()
            if suppressions is not None
            else None
        )
    )
    report = apply_admission(
        report,
        baseline=baseline,
        suppressions=suppressions,
        evaluated_on=evaluated_on,
    )
    if policy is not None:
        report = apply_policy(
            report,
            policy,
            baseline=baseline,
            suppressions=suppressions,
        )
    return report


def _report_is_blocked(
    report: ScanReport,
    *,
    fail_on: str,
) -> bool:
    return (
        report.policy is not None
        and report.policy["result"]["blocked"]
    ) or _threshold_reached(report, fail_on)


def _evidence_materials(
    report: ScanReport,
    arguments: argparse.Namespace,
) -> dict[str, bytes]:
    paths = {
        "baseline": arguments.baseline,
        "generation_plan": arguments.generation_plan,
        "policy": arguments.policy,
        "scope_plan": arguments.scope_plan,
        "suppressions": arguments.suppressions,
    }
    materials: dict[str, bytes] = {}
    for name, digest in expected_material_digests(report).items():
        path = paths[name]
        if not path:
            raise EvidenceError(
                f"report retained {name} without a corresponding input path"
            )
        materials[name] = read_evidence_material(
            path,
            expected_digest=digest,
        )
    return materials


def _render_verification_summary(summary: dict[str, object]) -> str:
    component = summary["component"]
    assert isinstance(component, dict)
    return "\n".join(
        (
            f"PgExtAssure evidence {summary['schema_version']}: valid",
            (
                f"Component: {component['name']}"
                + (
                    f" {component['version']}"
                    if component["version"] is not None
                    else ""
                )
            ),
            f"Gate: {summary['gate']}",
            f"Manifest: {summary['manifest_digest']}",
            f"Coverage: {summary['coverage_digest']}",
            "Source files included: no",
            "Dependency resolution: not performed",
        )
    ) + "\n"


def _render_signature_summary(summary: dict[str, object]) -> str:
    return "\n".join(
        (
            f"PgExtAssure corporate signature {summary['schema_version']}: valid",
            f"Signer: {summary['signer_id']}",
            f"Profile: {summary['profile']}",
            f"Gate: {summary['gate']}",
            f"Subject: {summary['subject_digest']}",
            f"Public key: {summary['public_key_sha256']}",
        )
    ) + "\n"


def _render_trust_summary(summary: dict[str, object]) -> str:
    reasons = summary["reasons"]
    assert isinstance(reasons, list)
    return "\n".join(
        (
            f"PgExtAssure admission receipt {summary['schema_version']}: valid",
            f"Decision: {summary['decision']}",
            (
                "Active: "
                + (
                    "yes"
                    if summary.get(
                        "active",
                        summary["decision"] == "admit",
                    )
                    else "no"
                )
            ),
            f"Request: {summary['request_id']}",
            f"Target: {summary['target']}",
            f"Evaluated on: {summary['evaluated_on']}",
            f"Valid until: {summary['valid_until']}",
            (
                "Reasons: "
                + (
                    ", ".join(str(reason) for reason in reasons)
                    if reasons
                    else "none"
                )
            ),
            f"Trust policy: {summary['trust_policy_digest']}",
            f"Subject: {summary['subject_digest']}",
            f"Signer: {summary['signer_id']}",
        )
    ) + "\n"


def _render_pilot_summary(summary: dict[str, object]) -> str:
    lines = [
        f"PgExtAssure enterprise pilot package {summary['schema_version']}: valid",
        f"Files: {summary['files']}",
        f"Archive: {summary['archive_sha256']}",
    ]
    if "wheel" in summary:
        lines.extend(
            (
                f"Wheel: {summary['wheel']}",
                f"Source distribution: {summary['source_distribution']}",
            )
        )
    return "\n".join(lines) + "\n"


def _silence_broken_stdout() -> None:
    """Prevent Python's shutdown flush from replacing the intended exit code."""

    try:
        stdout_descriptor = sys.stdout.fileno()
        null_descriptor = os.open(os.devnull, os.O_WRONLY)
        if null_descriptor != stdout_descriptor:
            try:
                os.dup2(null_descriptor, stdout_descriptor)
            finally:
                os.close(null_descriptor)
    except (AttributeError, OSError, TypeError, ValueError):
        # A non-file test stream may have no usable descriptor. Its failed
        # write is already contained and cannot trigger a real shutdown flush.
        pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)

    if arguments.command == "gateway" and arguments.gateway_command == "serve":
        try:
            if (
                not is_loopback_host(arguments.host)
                and not arguments.allow_remote
            ):
                raise GatewayError(
                    "non-loopback bind requires explicit --allow-remote"
                )
            server = create_gateway_server(
                GatewayConfig(
                    host=arguments.host,
                    port=arguments.port,
                    ledger_path=(
                        Path(arguments.ledger) if arguments.ledger else None
                    ),
                    postgres_dsn_file=(
                        Path(arguments.postgres_dsn_file)
                        if arguments.postgres_dsn_file
                        else None
                    ),
                    initialize_postgres_ledger=(
                        arguments.initialize_postgres_ledger
                    ),
                    maximum_request_bytes=arguments.maximum_request_bytes,
                    maximum_concurrent_requests=(
                        arguments.maximum_concurrent_requests
                    ),
                    request_timeout_seconds=(
                        arguments.request_timeout_seconds
                    ),
                    openssl_path=arguments.openssl,
                )
            )
            host, port = server.server_address[:2]
            sys.stdout.write(
                f"PgExtAssure admission gateway listening on {host}:{port}\n"
            )
            sys.stdout.flush()
            try:
                server.serve_forever(poll_interval=0.5)
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return EXIT_OK
        except GatewayError as error:
            print(
                f"pgextassure: gateway: {sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        except OSError as error:
            print(
                "pgextassure: gateway startup failed: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE

    if (
        arguments.command == "integration"
        and arguments.integration_command == "export"
    ):
        try:
            destinations = [
                os.path.abspath(value)
                for value in (
                    arguments.output,
                    arguments.manifest_output,
                )
                if value
            ]
            if os.path.abspath(arguments.path) in destinations:
                raise IntegrationError(
                    "integration outputs must not overwrite the Admission Event"
                )
            if len(destinations) != len(set(destinations)):
                raise IntegrationError(
                    "integration payload and manifest outputs must be distinct"
                )
            projection = project_admission_event(
                arguments.path,
                profile=arguments.profile,
                project=arguments.project,
                issue_type=arguments.issue_type,
                table=arguments.table,
                index=arguments.index,
            )
            if arguments.output:
                _write_binary_output(arguments.output, projection.payload)
                sys.stdout.write(
                    f"PgExtAssure integration export: {projection.profile}\n"
                    f"Media type: {projection.media_type}\n"
                    f"Output: {arguments.output}\n"
                )
            else:
                sys.stdout.write(projection.payload.decode("utf-8"))
            if arguments.manifest_output:
                _write_binary_output(
                    arguments.manifest_output,
                    projection.manifest,
                )
            sys.stdout.flush()
            return EXIT_OK
        except AdmissionEventError as error:
            print(
                "pgextassure: Admission Event verification failed: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_SCAN_ERROR
        except IntegrationError as error:
            print(
                f"pgextassure: integration: {sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        except BrokenPipeError:
            _silence_broken_stdout()
            return EXIT_OK
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE

    if arguments.command == "pilot" and arguments.pilot_command == "package":
        try:
            output_path = os.path.abspath(arguments.output)
            staging_path = os.path.abspath(arguments.path)
            if os.path.commonpath((output_path, staging_path)) == staging_path:
                raise PilotPackageError(
                    "pilot package output must be outside its staging directory"
                )
            package = create_pilot_package(arguments.path)
            _write_binary_output(arguments.output, package.archive)
            rendered = (
                json.dumps(
                    package.summary,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
                if arguments.output_format == "json"
                else _render_pilot_summary(package.summary)
            )
            sys.stdout.write(rendered)
            sys.stdout.flush()
            return EXIT_OK
        except PilotPackageError as error:
            print(
                f"pgextassure: pilot package: {sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        except BrokenPipeError:
            _silence_broken_stdout()
            return EXIT_OK
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE

    if (
        arguments.command == "pilot"
        and arguments.pilot_command == "verify-package"
    ):
        try:
            verification = verify_pilot_package(arguments.path)
            rendered = (
                json.dumps(
                    verification.summary,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
                if arguments.output_format == "json"
                else _render_pilot_summary(verification.summary)
            )
            sys.stdout.write(rendered)
            sys.stdout.flush()
            return EXIT_OK
        except PilotPackageError as error:
            print(
                f"pgextassure: pilot package verification failed: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_SCAN_ERROR
        except BrokenPipeError:
            _silence_broken_stdout()
            return EXIT_OK

    if arguments.command == "pilot" and arguments.pilot_command == "enforce":
        try:
            expected_evaluated_on = parse_admission_date(
                arguments.expected_evaluated_on,
                label="pilot expected_evaluated_on",
            )
            verified_on = (
                parse_admission_date(
                    arguments.verified_on,
                    label="pilot verified_on",
                )
                if arguments.verified_on
                else datetime.now(timezone.utc).date()
            )
            if arguments.event_output:
                protected_paths = {os.path.abspath(arguments.path)}
                if arguments.openssl:
                    protected_paths.add(os.path.abspath(arguments.openssl))
                if os.path.abspath(arguments.event_output) in protected_paths:
                    raise AdmissionEnforcementError(
                        "Admission Event output must not overwrite an input"
                    )
            enforcement = enforce_pilot_package(
                arguments.path,
                expected_package_sha256=arguments.expected_package_sha256,
                expected_public_key_sha256=arguments.expected_key_sha256,
                expected_trust_policy_sha256=(
                    arguments.expected_trust_policy_sha256
                ),
                expected_request_id=arguments.expected_request_id,
                expected_target=arguments.expected_target,
                expected_evaluated_on=expected_evaluated_on,
                verified_on=verified_on,
                openssl_path=arguments.openssl,
            )
            if arguments.event_output:
                _write_binary_output(arguments.event_output, enforcement.event)
            rendered = (
                enforcement.event.decode("utf-8")
                if arguments.output_format == "json"
                else (
                    "PgExtAssure Admission Event 1.0: "
                    f"{enforcement.document['outcome']}\n"
                    f"Event ID: {enforcement.document['id']}\n"
                    "Package: "
                    f"{enforcement.document['package']['digest']}\n"
                    "Request: "
                    f"{enforcement.document['request']['id']}\n"
                    "Target: "
                    f"{enforcement.document['request']['target']}\n"
                    "Valid until: "
                    f"{enforcement.document['decision']['valid_until']}\n"
                )
            )
            sys.stdout.write(rendered)
            sys.stdout.flush()
            return EXIT_OK if enforcement.active else EXIT_FINDINGS
        except AdmissionError as error:
            print(
                f"pgextassure: pilot enforcement: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        except AdmissionEnforcementError as error:
            print(
                f"pgextassure: pilot enforcement failed: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_SCAN_ERROR
        except BrokenPipeError:
            _silence_broken_stdout()
            return EXIT_OK if enforcement.active else EXIT_FINDINGS
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE

    if arguments.command == "review":
        try:
            if arguments.review_command == "template":
                _write_output(
                    arguments.output,
                    render_decision_template(arguments.path),
                )
                return EXIT_OK
            summary = verify_decision_ledger(
                arguments.path,
                arguments.ledger,
            )
            rendered = (
                json.dumps(
                    summary,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
                if arguments.output_format == "json"
                else (
                    "PgExtAssure decision ledger 1.0: valid\n"
                    f"Decisions: {summary['decisions']}\n"
                    "Admission authority: no\n"
                )
            )
            sys.stdout.write(rendered)
            sys.stdout.flush()
        except ReviewError as error:
            print(
                f"pgextassure: review: {sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        except BrokenPipeError:
            _silence_broken_stdout()
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        return EXIT_OK

    if arguments.command == "policy-template":
        try:
            rendered = render_policy_template(arguments.profile)
            if arguments.output:
                _write_output(arguments.output, rendered)
            else:
                sys.stdout.write(rendered)
                sys.stdout.flush()
        except PolicyError as error:
            print(
                f"pgextassure: policy: {sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        except BrokenPipeError:
            _silence_broken_stdout()
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        return EXIT_OK

    if arguments.command == "trust" and arguments.trust_command == "evaluate":
        try:
            output_path = os.path.abspath(arguments.output)
            protected_paths = {
                os.path.abspath(value)
                for value in (
                    arguments.path,
                    arguments.statement,
                    arguments.signature,
                    arguments.public_key,
                    arguments.trust_policy,
                )
            }
            if arguments.openssl:
                protected_paths.add(os.path.abspath(arguments.openssl))
            if output_path in protected_paths:
                raise TrustPolicyError(
                    "admission receipt must not overwrite a trust input"
                )
            evaluated_on = (
                parse_admission_date(
                    arguments.evaluated_on,
                    label="trust evaluated_on",
                )
                if arguments.evaluated_on
                else datetime.now(timezone.utc).date()
            )
            receipt = evaluate_admission(
                arguments.path,
                statement_path=arguments.statement,
                signature_path=arguments.signature,
                public_key_path=arguments.public_key,
                trust_policy_path=arguments.trust_policy,
                evaluated_on=evaluated_on,
                request_id=arguments.request_id,
                target=arguments.target,
                openssl_path=arguments.openssl,
            )
            _write_binary_output(arguments.output, receipt.receipt)
            rendered = (
                json.dumps(
                    receipt.summary,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
                if arguments.output_format == "json"
                else _render_trust_summary(receipt.summary)
            )
            sys.stdout.write(rendered)
            sys.stdout.flush()
            return (
                EXIT_OK
                if receipt.summary["decision"] == "admit"
                else EXIT_FINDINGS
            )
        except (TrustPolicyError, AdmissionError) as error:
            print(
                f"pgextassure: enterprise trust policy: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        except TrustVerificationError as error:
            print(
                f"pgextassure: trust verification failed: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_SCAN_ERROR
        except BrokenPipeError:
            _silence_broken_stdout()
            return (
                EXIT_OK
                if receipt.summary["decision"] == "admit"
                else EXIT_FINDINGS
            )
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE

    if (
        arguments.command == "trust"
        and arguments.trust_command == "verify-receipt"
    ):
        try:
            verified_on = (
                parse_admission_date(
                    arguments.verified_on,
                    label="receipt verified_on",
                )
                if arguments.verified_on
                else datetime.now(timezone.utc).date()
            )
            expected_evaluated_on = parse_admission_date(
                arguments.expected_evaluated_on,
                label="receipt expected_evaluated_on",
            )
            verification = verify_admission_receipt(
                arguments.path,
                arguments.bundle,
                statement_path=arguments.statement,
                signature_path=arguments.signature,
                public_key_path=arguments.public_key,
                trust_policy_path=arguments.trust_policy,
                verified_on=verified_on,
                expected_request_id=arguments.expected_request_id,
                expected_target=arguments.expected_target,
                expected_evaluated_on=expected_evaluated_on,
                expected_trust_policy_sha256=(
                    arguments.expected_trust_policy_sha256
                ),
                openssl_path=arguments.openssl,
            )
            rendered = (
                json.dumps(
                    verification.summary,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
                if arguments.output_format == "json"
                else _render_trust_summary(verification.summary)
            )
            sys.stdout.write(rendered)
            sys.stdout.flush()
            return EXIT_OK if verification.summary["active"] else EXIT_FINDINGS
        except (TrustPolicyError, AdmissionError) as error:
            print(
                f"pgextassure: enterprise trust policy: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        except TrustVerificationError as error:
            print(
                f"pgextassure: admission receipt verification failed: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_SCAN_ERROR
        except BrokenPipeError:
            _silence_broken_stdout()
            return (
                EXIT_OK
                if verification.summary["active"]
                else EXIT_FINDINGS
            )
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE

    if (
        arguments.command == "evidence"
        and arguments.evidence_command == "sign"
    ):
        try:
            outputs = (
                arguments.statement_output,
                arguments.signature_output,
                arguments.public_key_output,
            )
            output_paths = {os.path.abspath(value) for value in outputs}
            if len(output_paths) != len(outputs):
                raise SigningError("signature output paths must be distinct")
            protected_paths = {
                os.path.abspath(arguments.path),
                os.path.abspath(arguments.private_key),
            }
            if arguments.openssl:
                protected_paths.add(os.path.abspath(arguments.openssl))
            if output_paths & protected_paths:
                raise SigningError(
                    "signature outputs must not overwrite signing inputs"
                )
            passphrase = None
            if arguments.passphrase_env:
                if arguments.passphrase_env not in os.environ:
                    raise SigningError(
                        "private-key passphrase environment variable is absent"
                    )
                passphrase = os.environ[arguments.passphrase_env]
            created_on = (
                parse_admission_date(
                    arguments.created_on,
                    label="signature created_on",
                )
                if arguments.created_on
                else datetime.now(timezone.utc).date()
            )
            signed = sign_evidence_bundle(
                arguments.path,
                private_key_path=arguments.private_key,
                signer_id=arguments.signer_id,
                created_on=created_on,
                passphrase=passphrase,
                openssl_path=arguments.openssl,
            )
            _write_binary_output(arguments.statement_output, signed.statement)
            _write_binary_output(arguments.signature_output, signed.signature)
            _write_binary_output(arguments.public_key_output, signed.public_key)
            sys.stdout.write(_render_signature_summary(signed.summary))
            sys.stdout.flush()
        except (SigningError, AdmissionError) as error:
            print(
                f"pgextassure: corporate signing: {sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        except BrokenPipeError:
            _silence_broken_stdout()
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        return EXIT_OK

    if (
        arguments.command == "evidence"
        and arguments.evidence_command == "verify-signature"
    ):
        try:
            verification = verify_evidence_signature(
                arguments.path,
                statement_path=arguments.statement,
                signature_path=arguments.signature,
                public_key_path=arguments.public_key,
                expected_public_key_sha256=arguments.expected_key_sha256,
                openssl_path=arguments.openssl,
            )
            rendered = (
                json.dumps(
                    verification.summary,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
                if arguments.output_format == "json"
                else _render_signature_summary(verification.summary)
            )
            sys.stdout.write(rendered)
            sys.stdout.flush()
        except SigningError as error:
            print(
                "pgextassure: corporate signature verification failed: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_SCAN_ERROR
        except BrokenPipeError:
            _silence_broken_stdout()
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        return EXIT_OK

    if (
        arguments.command == "evidence"
        and arguments.evidence_command == "verify"
    ):
        try:
            verification = verify_evidence_bundle(arguments.path)
            if arguments.predicate_output:
                _write_output(
                    arguments.predicate_output,
                    json.dumps(
                        verification.predicate,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        indent=2,
                    )
                    + "\n",
                )
            if arguments.sbom_output:
                _write_output(
                    arguments.sbom_output,
                    json.dumps(
                        verification.sbom,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        indent=2,
                    )
                    + "\n",
                )
            rendered = (
                json.dumps(
                    verification.summary,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
                if arguments.output_format == "json"
                else _render_verification_summary(verification.summary)
            )
            sys.stdout.write(rendered)
            sys.stdout.flush()
        except EvidenceError as error:
            print(
                "pgextassure: evidence verification failed: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_SCAN_ERROR
        except BrokenPipeError:
            _silence_broken_stdout()
        except OSError as error:
            print(
                "pgextassure: cannot write output: "
                f"{sanitize_terminal_text(error)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        return EXIT_OK

    try:
        if (
            arguments.command == "evidence"
            and arguments.evidence_command == "create"
        ):
            report = _controlled_scan(arguments)
            created_on = (
                parse_admission_date(
                    arguments.created_on,
                    label="evidence created_on",
                )
                if arguments.created_on
                else datetime.now(timezone.utc).date()
            )
            blocked = _report_is_blocked(
                report,
                fail_on=arguments.fail_on,
            )
            bundle = create_evidence_bundle(
                report,
                created_on=created_on,
                component_name=arguments.component_name,
                component_version=arguments.component_version,
                blocked=blocked,
                fail_on=(
                    "none"
                    if arguments.policy is not None
                    else arguments.fail_on
                ),
                materials=_evidence_materials(report, arguments),
            )
            _write_binary_output(arguments.output, bundle)
            verification = verify_evidence_bundle(arguments.output)
            sys.stdout.write(
                _render_verification_summary(verification.summary)
            )
            sys.stdout.flush()
            return EXIT_FINDINGS if blocked else EXIT_OK
        if (
            arguments.command == "scan"
            and arguments.github_annotations != "none"
            and not arguments.output
        ):
            raise ScanInputError(
                "--github-annotations requires --output so report stdout "
                "remains machine-readable"
            )
        if arguments.command == "baseline":
            generation_plan = (
                load_generation_plan(arguments.generation_plan)
                if arguments.generation_plan
                else None
            )
            scope_plan = (
                load_scope_plan(arguments.scope_plan)
                if arguments.scope_plan
                else None
            )
            report = scan_path(
                arguments.path,
                generation_plan=generation_plan,
                scope_plan=scope_plan,
            )
            created_on = (
                parse_admission_date(
                    arguments.created_on,
                    label="baseline created_on",
                )
                if arguments.created_on
                else datetime.now(timezone.utc).date()
            )
            rendered = render_baseline(report, created_on=created_on)
            result = EXIT_OK
        else:
            report = _controlled_scan(arguments)
            sarif_path_prefix = (
                _sarif_path_prefix(arguments.path)
                if arguments.output_format == "sarif"
                else ""
            )
            rendered = _render(
                report,
                arguments.output_format,
                sarif_path_prefix=sarif_path_prefix,
            )
            annotations = (
                render_github_annotations(
                    report,
                    mode=arguments.github_annotations,
                    path_prefix=_sarif_path_prefix(arguments.path),
                    maximum=arguments.max_annotations,
                )
                if arguments.github_annotations != "none"
                else ""
            )
            result = (
                EXIT_FINDINGS
                if _report_is_blocked(
                    report,
                    fail_on=arguments.fail_on,
                )
                else EXIT_OK
            )
    except GenerationPlanError as error:
        print(
            f"pgextassure: generation plan: {sanitize_terminal_text(error)}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    except ScopePlanError as error:
        print(
            f"pgextassure: scope plan: {sanitize_terminal_text(error)}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    except AdmissionError as error:
        print(
            f"pgextassure: admission: {sanitize_terminal_text(error)}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    except PolicyError as error:
        print(
            f"pgextassure: policy: {sanitize_terminal_text(error)}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    except EvidenceError as error:
        print(
            f"pgextassure: evidence: {sanitize_terminal_text(error)}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    except BrokenPipeError:
        _silence_broken_stdout()
        return (
            EXIT_FINDINGS
            if (
                arguments.command == "evidence"
                and arguments.evidence_command == "create"
                and blocked
            )
            else EXIT_OK
        )
    except OSError as error:
        print(
            "pgextassure: cannot write output: "
            f"{sanitize_terminal_text(error)}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    except ScanInputError as error:
        print(
            f"pgextassure: {sanitize_terminal_text(error)}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    except ScanError as error:
        print(
            f"pgextassure: scan failed: {sanitize_terminal_text(error)}",
            file=sys.stderr,
        )
        return EXIT_SCAN_ERROR

    try:
        if arguments.output:
            _write_output(arguments.output, rendered)
        else:
            sys.stdout.write(rendered)
            sys.stdout.flush()
        if arguments.command == "scan" and annotations:
            sys.stdout.write(annotations)
            sys.stdout.flush()
    except BrokenPipeError:
        _silence_broken_stdout()
        return result
    except OSError as error:
        print(
            "pgextassure: cannot write output: "
            f"{sanitize_terminal_text(error)}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    return result
