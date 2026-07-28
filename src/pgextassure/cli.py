"""Command-line interface for PgExtAssure."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile
from typing import Sequence

from .generation import GenerationPlanError, load_generation_plan
from .models import SEVERITY_RANK, ScanReport, Severity
from .reporting import (
    render_grouped_json,
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
    if arguments.command != "scan":
        parser.error("a command is required")

    try:
        generation_plan = (
            load_generation_plan(arguments.generation_plan)
            if arguments.generation_plan
            else None
        )
        report = scan_path(
            arguments.path,
            generation_plan=generation_plan,
        )
    except GenerationPlanError as error:
        print(
            f"pgextassure: generation plan: {sanitize_terminal_text(error)}",
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
    result = (
        EXIT_FINDINGS
        if _threshold_reached(report, arguments.fail_on)
        else EXIT_OK
    )
    try:
        if arguments.output:
            _write_output(arguments.output, rendered)
        else:
            sys.stdout.write(rendered)
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
