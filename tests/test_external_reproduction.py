"""Disclosure-safe external reproduction kit regression tests."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from pgextassure import __release_version__
from tests.support import PROJECT_ROOT, run_cli


REPRODUCTION_ROOT = PROJECT_ROOT / "validation" / "external-reproduction"


class ExternalReproductionTests(unittest.TestCase):
    def test_protocol_remains_pinned_to_the_reproduced_alpha16_release(self) -> None:
        workflow_path = (
            PROJECT_ROOT / ".github/workflows/external-reproduction.yml"
        )
        verifier_path = PROJECT_ROOT / "tools/verify_external_reproduction.py"
        workflow = workflow_path.read_text(encoding="utf-8")
        verifier = verifier_path.read_text(encoding="utf-8")

        self.assertIn(
            "ref: 96e0f14fe8f2f86a11be1341f87ddece9385a8b2",
            workflow,
        )
        self.assertIn('"tool_version": "0.1.0-alpha.16"', verifier)

    def test_controlled_protocol_produces_expected_report(self) -> None:
        if __release_version__ != "0.1.0-alpha.16":
            self.skipTest(
                "the disclosure-safe reproduction protocol is frozen to alpha.16"
            )

        with TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "scanner-evidence.zip"
            predicate = root / "scanner-predicate.json"
            sbom = root / "scanner-sbom.spdx.json"
            shadowing = root / "security-definer-shadowing.txt"
            trigger = root / "security-definer-trigger.txt"
            postgres_version = root / "postgres-version.txt"
            output = root / "external-reproduction-report.json"

            creation = run_cli(
                "evidence",
                "create",
                str(REPRODUCTION_ROOT / "fixtures"),
                "--created-on",
                "2026-08-08",
                "--component-name",
                "pgextassure-external-reproduction-fixture",
                "--component-version",
                "1.0",
                "--fail-on",
                "none",
                "--output",
                str(evidence),
            )
            verification = run_cli(
                "evidence",
                "verify",
                str(evidence),
                "--predicate-output",
                str(predicate),
                "--sbom-output",
                str(sbom),
            )
            self.assertEqual(0, creation.returncode, creation.stderr)
            self.assertEqual(0, verification.returncode, verification.stderr)

            shadowing.write_text(
                "EXTERNAL_REPRODUCTION|security-definer-shadowing|PASS\n",
                encoding="utf-8",
            )
            trigger.write_text(
                "EXTERNAL_REPRODUCTION|security-definer-trigger|PASS\n",
                encoding="utf-8",
            )
            postgres_version.write_text(
                "16.13 (Debian 16.13-1.pgdg12+1)\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "tools" / "verify_external_reproduction.py"),
                    "--evidence",
                    str(evidence),
                    "--predicate",
                    str(predicate),
                    "--sbom",
                    str(sbom),
                    "--shadowing-output",
                    str(shadowing),
                    "--trigger-output",
                    str(trigger),
                    "--postgres-version-output",
                    str(postgres_version),
                    "--repository",
                    "external-reviewer/pgextassure",
                    "--workflow-revision",
                    "0" * 40,
                    "--run-url",
                    "https://github.com/external-reviewer/pgextassure/actions/runs/1",
                    "--actor",
                    "external-reviewer",
                    "--runner-os",
                    "Linux",
                    "--runner-arch",
                    "X64",
                    "--output",
                    str(output),
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual("pass", report["outcome"])
        self.assertEqual("0.1.0-alpha.16", report["tool"]["version"])
        self.assertEqual(
            "sha256:e4a7b2e46591ca0519345664a77c203bcced7532cf2733dbe372376e10c53790",
            report["artifacts"]["evidence"],
        )
        self.assertEqual(
            [
                "scanner-evidence",
                "security-definer-shadowing",
                "security-definer-trigger",
            ],
            [check["id"] for check in report["checks"]],
        )


if __name__ == "__main__":
    unittest.main()
