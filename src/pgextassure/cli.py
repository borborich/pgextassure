"""Command-line interface for PgExtAssure."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
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
from .generation import GenerationPlanError, load_generation_plan
from .models import SEVERITY_RANK, ScanReport, Severity
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
from .scanner import TOOL_VERSION, ScanError, ScanInputError, scan_path


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
        choices=("text", "json", "grouped-json", "sarif"),
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
    policy_template = subcommands.add_parser(
        "policy-template",
        help="write a packaged organization policy template for review",
    )
    policy_template.add_argument(
        "profile",
        choices=POLICY_TEMPLATE_PROFILES,
    )
    policy_template.add_argument("--output", metavar="FILE")
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


def _write_output(path: str, rendered: str) -> None:
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
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
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

    try:
        if (
            arguments.command == "scan"
            and arguments.github_annotations != "none"
            and not arguments.output
        ):
            raise ScanInputError(
                "--github-annotations requires --output so report stdout "
                "remains machine-readable"
            )
        generation_plan = (
            load_generation_plan(arguments.generation_plan)
            if arguments.generation_plan
            else None
        )
        report = scan_path(
            arguments.path,
            generation_plan=generation_plan,
        )
        if arguments.command == "baseline":
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
            policy = (
                load_policy(arguments.policy) if arguments.policy else None
            )
            if policy is not None and arguments.fail_on != "none":
                raise PolicyError(
                    "--policy cannot be combined with --fail-on; "
                    "the policy owns the gate"
                )
            baseline = (
                load_baseline(arguments.baseline)
                if arguments.baseline
                else None
            )
            suppressions = (
                load_suppressions(arguments.suppressions)
                if arguments.suppressions
                else None
            )
            if arguments.evaluated_on and suppressions is None:
                raise AdmissionError(
                    "--evaluated-on requires --suppressions"
                )
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
                if (
                    report.policy is not None
                    and report.policy["result"]["blocked"]
                )
                or _threshold_reached(report, arguments.fail_on)
                else EXIT_OK
            )
    except GenerationPlanError as error:
        print(
            f"pgextassure: generation plan: {sanitize_terminal_text(error)}",
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
