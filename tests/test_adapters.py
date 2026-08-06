"""Tests for strict external-analyzer evidence normalization."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.adapters import (
    ExternalAnalysisError,
    normalize_pgspot,
    render_external_analysis,
    verify_external_analysis,
)
from tests.support import parse_json_stdout, run_cli


PGSPOT_RESULT = (
    "PS003: SECURITY DEFINER function without explicit search_path: "
    "unsafe_sec_definer2() at line 1\n"
    "PS001: Unqualified object reference: public.demo at line 2\n"
    "\n Errors: 1 Warnings: 1 Unknown: 0 \n\n"
)


class ExternalAnalyzerAdapterTests(unittest.TestCase):
    def _inputs(self, root: Path, output: str = PGSPOT_RESULT) -> tuple[Path, Path]:
        source = root / "extension.sql"
        stdout = root / "pgspot.stdout"
        source.write_text("SELECT 1;\nSELECT 2;\n", encoding="utf-8")
        stdout.write_text(output, encoding="utf-8")
        return source, stdout

    def test_pgspot_normalization_is_deterministic_and_digest_bound(self) -> None:
        with TemporaryDirectory() as directory:
            source, stdout = self._inputs(Path(directory))
            first = normalize_pgspot(
                source,
                stdout,
                subject_path="sql/extension.sql",
                analyzer_version="0.9.2",
                exit_code=1,
            )
            second = normalize_pgspot(
                source,
                stdout,
                subject_path="sql/extension.sql",
                analyzer_version="0.9.2",
                exit_code=1,
            )

        self.assertEqual(first, second)
        self.assertEqual(
            render_external_analysis(first),
            render_external_analysis(second),
        )
        self.assertEqual("declared", first["analyzer"]["version_evidence"])
        self.assertEqual(
            {"diagnostics": 2, "errors": 1, "warnings": 1, "unknown": 0},
            first["summary"],
        )
        self.assertEqual(
            ["error", "warning"],
            [item["level"] for item in first["diagnostics"]],
        )
        self.assertTrue(first["subject"]["sha256"].startswith("sha256:"))
        self.assertTrue(first["input"]["stdout_sha256"].startswith("sha256:"))

    def test_clean_result_requires_zero_exit_code(self) -> None:
        with TemporaryDirectory() as directory:
            source, stdout = self._inputs(
                Path(directory),
                " Errors: 0 Warnings: 0 Unknown: 0 \n",
            )
            document = normalize_pgspot(
                source,
                stdout,
                subject_path="extension.sql",
                analyzer_version="0.9.2",
                exit_code=0,
            )

        self.assertEqual([], document["diagnostics"])
        self.assertEqual(0, document["summary"]["diagnostics"])

    def test_unknown_lines_counts_rules_versions_and_exit_codes_fail_closed(self) -> None:
        cases = (
            ("banner\nErrors: 0 Warnings: 0 Unknown: 0\n", "unrecognized"),
            (
                "PS003: title: context at line 1\n"
                "Errors: 0 Warnings: 0 Unknown: 0\n",
                "summary does not match",
            ),
            (
                "PS008: title: context at line 1\n"
                "Errors: 1 Warnings: 0 Unknown: 0\n",
                "unsupported pgspot rule",
            ),
            ("Errors: 0 Warnings: 0 Unknown: 1\n", "unknown diagnostics"),
        )
        for output, message in cases:
            with self.subTest(message=message), TemporaryDirectory() as directory:
                source, stdout = self._inputs(Path(directory), output)
                with self.assertRaisesRegex(ExternalAnalysisError, message):
                    normalize_pgspot(
                        source,
                        stdout,
                        subject_path="extension.sql",
                        analyzer_version="0.9.2",
                        exit_code=1,
                    )

        with TemporaryDirectory() as directory:
            source, stdout = self._inputs(Path(directory))
            with self.assertRaisesRegex(ExternalAnalysisError, "unsupported pgspot version"):
                normalize_pgspot(
                    source,
                    stdout,
                    subject_path="extension.sql",
                    analyzer_version="0.9.3",
                    exit_code=1,
                )
            with self.assertRaisesRegex(ExternalAnalysisError, "exit code"):
                normalize_pgspot(
                    source,
                    stdout,
                    subject_path="extension.sql",
                    analyzer_version="0.9.2",
                    exit_code=0,
                )

    def test_verifier_rebuilds_and_detects_source_or_stdout_tampering(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source, stdout = self._inputs(root)
            document_path = root / "external.json"
            document = normalize_pgspot(
                source,
                stdout,
                subject_path="sql/extension.sql",
                analyzer_version="0.9.2",
                exit_code=1,
            )
            document_path.write_bytes(render_external_analysis(document))

            verified = verify_external_analysis(document_path, source, stdout)
            self.assertEqual(document, verified)

            source.write_text("SELECT 3;\n", encoding="utf-8")
            with self.assertRaisesRegex(ExternalAnalysisError, "does not match"):
                verify_external_analysis(document_path, source, stdout)

    def test_duplicate_noncanonical_and_symlinked_inputs_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source, stdout = self._inputs(root)
            document_path = root / "external.json"
            document = normalize_pgspot(
                source,
                stdout,
                subject_path="extension.sql",
                analyzer_version="0.9.2",
                exit_code=1,
            )
            noncanonical = json.dumps(document, indent=2).encode("utf-8") + b"\n"
            document_path.write_bytes(noncanonical)
            with self.assertRaisesRegex(ExternalAnalysisError, "not canonical"):
                verify_external_analysis(document_path, source, stdout)

            document_path.write_text(
                '{"schema_version":"1.0","schema_version":"1.0"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ExternalAnalysisError, "duplicate JSON key"):
                verify_external_analysis(document_path, source, stdout)

            if hasattr(os, "symlink"):
                alias = root / "source-link.sql"
                alias.symlink_to(source.name)
                with self.assertRaisesRegex(ExternalAnalysisError, "non-symlink"):
                    normalize_pgspot(
                        alias,
                        stdout,
                        subject_path="extension.sql",
                        analyzer_version="0.9.2",
                        exit_code=1,
                    )

    def test_cli_normalizes_and_independently_verifies(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source, stdout = self._inputs(root)
            document = root / "external.json"
            normalized = run_cli(
                "adapter",
                "pgspot",
                str(source),
                "--stdout",
                str(stdout),
                "--subject-path",
                "sql/extension.sql",
                "--analyzer-version",
                "0.9.2",
                "--exit-code",
                "1",
                "--output",
                str(document),
            )
            verified = run_cli(
                "adapter",
                "verify",
                str(document),
                "--source",
                str(source),
                "--stdout",
                str(stdout),
                "--format",
                "json",
            )

        self.assertEqual(0, normalized.returncode, normalized.stderr)
        self.assertEqual(0, verified.returncode, verified.stderr)
        self.assertTrue(parse_json_stdout(verified)["valid"])


if __name__ == "__main__":
    unittest.main()
