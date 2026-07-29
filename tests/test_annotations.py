"""GitHub workflow annotation contract tests."""

from __future__ import annotations

from importlib.resources import files
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.support import FIXTURES_ROOT, VULNERABLE_ROOT, run_cli


class GitHubAnnotationTests(unittest.TestCase):
    def test_annotations_require_a_separate_report_output(self) -> None:
        result = run_cli(
            "scan",
            str(VULNERABLE_ROOT),
            "--format",
            "json",
            "--github-annotations",
            "active",
        )

        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn("requires --output", result.stderr)

    def test_annotation_is_root_cause_grouped_escaped_and_evidence_free(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "danger%,:\n.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'private-command';\n",
                encoding="utf-8",
            )
            report = root / "report.json"

            result = run_cli(
                "scan",
                str(source),
                "--format",
                "json",
                "--output",
                str(report),
                "--github-annotations",
                "active",
            )
            document = json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        self.assertTrue(result.stdout.startswith("::error file="))
        self.assertIn("danger%25%2C%3A\\u000a.sql", result.stdout)
        self.assertIn("title=PgExtAssure sql.copy-program [active]", result.stdout)
        self.assertNotIn("private-command", result.stdout)
        self.assertEqual(1, len(document["findings"]))

    def test_active_mode_omits_suppressed_root_causes(self) -> None:
        fixture = FIXTURES_ROOT / "admission"
        suppressions = fixture / "suppressions.json"
        with TemporaryDirectory() as directory:
            active_report = Path(directory) / "active.json"
            all_report = Path(directory) / "all.json"
            common = (
                "scan",
                str(fixture),
                "--suppressions",
                str(suppressions),
                "--evaluated-on",
                "2026-07-29",
                "--format",
                "json",
            )
            active = run_cli(
                *common,
                "--output",
                str(active_report),
                "--github-annotations",
                "active",
            )
            all_results = run_cli(
                *common,
                "--output",
                str(all_report),
                "--github-annotations",
                "all",
            )

        self.assertEqual(0, active.returncode, active.stderr)
        self.assertEqual("", active.stdout)
        self.assertEqual(0, all_results.returncode, all_results.stderr)
        self.assertTrue(all_results.stdout.startswith("::notice "))
        self.assertIn("[suppressed]", all_results.stdout)

    def test_annotation_limit_includes_truncation_notice(self) -> None:
        with TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            result = run_cli(
                "scan",
                str(VULNERABLE_ROOT),
                "--format",
                "json",
                "--output",
                str(report),
                "--github-annotations",
                "active",
                "--max-annotations",
                "2",
            )

        self.assertEqual(0, result.returncode, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(2, len(lines))
        self.assertIn("annotations truncated", lines[-1])

    def test_policy_coverage_violation_emits_unlocated_error(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            scan_root = root / "extension"
            scan_root.mkdir()
            (scan_root / "extension.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )
            (scan_root / "README.unsupported").write_text(
                "coverage fixture\n",
                encoding="utf-8",
            )
            policy = root / "policy.json"
            policy.write_text(
                files("pgextassure")
                .joinpath("policies", "strict.json")
                .read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            report = root / "report.json"

            result = run_cli(
                "scan",
                str(scan_root),
                "--format",
                "json",
                "--output",
                str(report),
                "--policy",
                str(policy),
                "--github-annotations",
                "active",
            )

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertTrue(
            result.stdout.startswith(
                "::error title=PgExtAssure policy coverage::"
            )
        )
        self.assertNotIn("file=", result.stdout)


if __name__ == "__main__":
    unittest.main()
