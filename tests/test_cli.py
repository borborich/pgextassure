from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pgextassure.cli import EXIT_FINDINGS, main
from pgextassure.reporting import to_sarif
from pgextassure.scanner import scan_path
from tests.support import SAFE_ROOT, VULNERABLE_ROOT, parse_json_stdout, run_cli


class CliContractTests(unittest.TestCase):
    def test_version_flag_reports_release_version(self) -> None:
        result = run_cli("--version")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("pgextassure 0.1.0-alpha.6\n", result.stdout)

    def test_output_symlink_is_rejected_without_overwriting_target(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            output = root / "report.json"
            target.write_text("do not overwrite\n", encoding="utf-8")
            output.symlink_to(target.name)

            result = run_cli(
                "scan",
                str(SAFE_ROOT),
                "--format",
                "json",
                "--output",
                str(output),
            )

            self.assertEqual(2, result.returncode, result.stderr)
            self.assertEqual(
                "do not overwrite\n",
                target.read_text(encoding="utf-8"),
            )
            self.assertIn("refusing symlink output", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires filesystem symlinks")
    def test_output_symlinked_directory_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            alias = root / "alias"
            alias.symlink_to(outside, target_is_directory=True)
            output = alias / "report.json"

            with patch.dict(
                os.environ,
                {"GITHUB_WORKSPACE": str(root)},
            ):
                result = run_cli(
                    "scan",
                    str(SAFE_ROOT),
                    "--format",
                    "json",
                    "--output",
                    str(output),
                )

            self.assertEqual(2, result.returncode, result.stderr)
            self.assertFalse((outside / "report.json").exists())
            self.assertIn("symlinked output directory", result.stderr)

    def test_text_output_escapes_hostile_filename_controls(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "danger\u001b[31m\n.sql"
            path.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )

            result = run_cli("scan", str(path), "--format", "text")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("\u001b", result.stdout)
        self.assertIn("\\u001b", result.stdout)
        self.assertIn("\\u000a", result.stdout)

    def test_json_output_is_valid_and_byte_deterministic(self) -> None:
        args = ("scan", str(VULNERABLE_ROOT), "--format", "json")
        first = run_cli(*args)
        second = run_cli(*args)
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(first.stdout, second.stdout)

        document = parse_json_stdout(first)
        self.assertIsInstance(document, dict)
        self.assertEqual("1.4", document.get("schema_version"))
        self.assertEqual("pgextassure", document.get("tool", {}).get("name"))
        self.assertIsInstance(document.get("findings"), list)
        self.assertRegex(
            document.get("manifest", {}).get("digest", ""),
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(
            len(document["findings"]),
            document.get("summary", {}).get("findings"),
        )
        self.assertEqual(
            {"critical", "high", "medium", "low"},
            set(document.get("summary", {}).get("by_severity", {})),
        )
        self.assertRegex(
            document.get("coverage", {}).get("digest", ""),
            r"^sha256:[0-9a-f]{64}$",
        )

    def test_sarif_output_is_valid_and_byte_deterministic(self) -> None:
        args = ("scan", str(VULNERABLE_ROOT), "--format", "sarif")
        first = run_cli(*args)
        second = run_cli(*args)
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(first.stdout, second.stdout)

        document = parse_json_stdout(first)
        self.assertEqual("2.1.0", document.get("version"))
        self.assertIsInstance(document.get("runs"), list)
        self.assertEqual(1, len(document["runs"]))
        self.assertIsInstance(document["runs"][0].get("results"), list)
        driver = document["runs"][0].get("tool", {}).get("driver", {})
        self.assertEqual("pgextassure", driver.get("name"))
        self.assertEqual("0.1.0-alpha.6", driver.get("semanticVersion"))
        self.assertEqual(
            "https://github.com/borborich/pgextassure",
            driver.get("informationUri"),
        )
        location_uris = [
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for result in document["runs"][0]["results"]
        ]
        self.assertTrue(location_uris)
        self.assertTrue(
            all(uri.startswith("tests/fixtures/vulnerable/") for uri in location_uris),
            location_uris,
        )
        for result in document["runs"][0]["results"]:
            self.assertIn(
                "pgextassure/v1",
                result.get("partialFingerprints", {}),
            )

    def test_sarif_prefix_is_repo_relative_and_uri_encoded(self) -> None:
        document = to_sarif(
            scan_path(VULNERABLE_ROOT),
            path_prefix="extensions/demo package",
        )
        location_uris = [
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for result in document["runs"][0]["results"]
        ]

        self.assertTrue(location_uris)
        self.assertTrue(
            all(
                uri.startswith("extensions/demo%20package/")
                for uri in location_uris
            ),
            location_uris,
        )

    def test_text_output_uses_product_display_name(self) -> None:
        result = run_cli("scan", str(SAFE_ROOT), "--format", "text")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(
            result.stdout.startswith("PgExtAssure 0.1.0-alpha.6\n"),
            result.stdout,
        )

    def test_fail_on_high_keeps_safe_scan_successful(self) -> None:
        result = run_cli(
            "scan",
            str(SAFE_ROOT),
            "--format",
            "json",
            "--fail-on",
            "high",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        document = parse_json_stdout(result)
        self.assertEqual([], document.get("findings"))

    def test_fail_on_high_fails_vulnerable_scan_but_still_emits_json(self) -> None:
        result = run_cli(
            "scan",
            str(VULNERABLE_ROOT),
            "--format",
            "json",
            "--fail-on",
            "high",
        )
        self.assertEqual(1, result.returncode, result.stderr)
        document = parse_json_stdout(result)
        self.assertTrue(document.get("findings"))

    def test_fail_threshold_obeys_severity_order(self) -> None:
        high_only_fixture = VULNERABLE_ROOT / "sql" / "public_execute.sql"
        below = run_cli(
            "scan",
            str(high_only_fixture),
            "--format",
            "json",
            "--fail-on",
            "critical",
        )
        reached = run_cli(
            "scan",
            str(high_only_fixture),
            "--format",
            "json",
            "--fail-on",
            "high",
        )
        self.assertEqual(0, below.returncode, below.stderr)
        self.assertEqual(1, reached.returncode, reached.stderr)
        self.assertTrue(parse_json_stdout(below).get("findings"))
        self.assertTrue(parse_json_stdout(reached).get("findings"))

    def test_broken_stdout_pipe_does_not_bypass_finding_gate(self) -> None:
        with patch("pgextassure.cli.sys.stdout") as stdout:
            stdout.write.side_effect = BrokenPipeError
            result = main(
                (
                    "scan",
                    str(VULNERABLE_ROOT),
                    "--format",
                    "json",
                    "--fail-on",
                    "high",
                )
            )

        self.assertEqual(EXIT_FINDINGS, result)

    def test_closed_subprocess_pipe_preserves_gate_exit_status(self) -> None:
        cases = (
            (SAFE_ROOT, 0),
            (VULNERABLE_ROOT, EXIT_FINDINGS),
        )
        for path, expected in cases:
            with self.subTest(path=path):
                with subprocess.Popen(
                    (
                        sys.executable,
                        "-m",
                        "pgextassure",
                        "scan",
                        str(path),
                        "--format",
                        "json",
                        "--fail-on",
                        "high",
                    ),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ) as process:
                    assert process.stdout is not None
                    assert process.stderr is not None
                    process.stdout.close()
                    stderr = process.stderr.read().decode(
                        "utf-8",
                        errors="replace",
                    )
                    result = process.wait(timeout=10)

            self.assertEqual(expected, result, stderr)
            self.assertNotIn("BrokenPipeError", stderr)

    def test_missing_path_is_a_usage_or_input_error_without_traceback(self) -> None:
        result = run_cli(
            "scan",
            str(SAFE_ROOT / "does-not-exist"),
            "--format",
            "json",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(result.stderr.startswith("pgextassure: "), result.stderr)
        self.assertNotIn("Traceback (most recent call last)", result.stderr)


if __name__ == "__main__":
    unittest.main()
