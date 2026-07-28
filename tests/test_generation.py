"""Contract tests for non-executing generated-artifact declarations."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import pgextassure.generation as generation
from pgextassure.generation import GenerationPlanError, load_generation_plan
from pgextassure.grouping import grouped_report_document
from pgextassure.reporting import render_text, to_sarif
from pgextassure.scanner import ScanInputError, scan_path
from tests.support import parse_json_stdout, rule_ids_from, run_cli


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _write_plan(root: Path, artifacts: list[dict[str, object]]) -> Path:
    path = root / "generation-plan.json"
    path.write_text(
        json.dumps(
            {"schema_version": "1.0", "artifacts": artifacts},
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


class GenerationPlanTests(unittest.TestCase):
    def test_declared_sql_artifact_completes_install_graph(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "demo.control").write_text(
                "default_version = '2.0'\nsuperuser = false\n",
                encoding="utf-8",
            )
            makefile = root / "Makefile"
            makefile.write_text(
                "all: sql/demo--2.0.sql\n",
                encoding="utf-8",
            )
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "sql/demo--2.0.sql",
                        "inputs": [
                            {
                                "path": "Makefile",
                                "sha256": _digest(makefile),
                            }
                        ],
                    }
                ],
            )

            baseline = scan_path(root)
            report = scan_path(
                root,
                generation_plan=load_generation_plan(plan_path),
            )

        self.assertIn("update.install-script-missing", rule_ids_from(baseline))
        self.assertNotIn("update.install-script-missing", rule_ids_from(report))
        self.assertEqual("1.1", report.schema_version)
        self.assertIsNotNone(report.generation)
        assert report.generation is not None
        self.assertEqual(
            "declared",
            report.generation["artifacts"][0]["mode"],
        )

    def test_rendered_control_resolves_default_version_without_build(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "demo.control.in"
            template.write_text(
                "default_version = 'EXTVERSION'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.0.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )
            (root / "demo--1.0--2.0.sql").write_text(
                "SELECT 2;\n",
                encoding="utf-8",
            )
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "demo.control",
                        "template": "demo.control.in",
                        "substitutions": {"EXTVERSION": "2.0"},
                        "inputs": [
                            {
                                "path": "demo.control.in",
                                "sha256": _digest(template),
                            }
                        ],
                    }
                ],
            )

            baseline = scan_path(root)
            report = scan_path(
                root,
                generation_plan=load_generation_plan(plan_path),
            )

        self.assertTrue(
            any(rule.startswith("update.") for rule in rule_ids_from(baseline))
        )
        self.assertFalse(
            any(rule.startswith("update.") for rule in rule_ids_from(report))
        )
        assert report.generation is not None
        artifact = report.generation["artifacts"][0]
        self.assertEqual("rendered", artifact["mode"])
        self.assertEqual(["EXTVERSION"], artifact["substitution_tokens"])
        self.assertRegex(
            artifact["rendered_sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )

    def test_rendered_sql_is_scanned_once_at_generated_path(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "demo.control").write_text(
                "default_version = '1.0'\nsuperuser = false\n",
                encoding="utf-8",
            )
            template = root / "demo.sql.in"
            template.write_text(
                "COPY demo FROM PROGRAM 'run-TOKEN';\n",
                encoding="utf-8",
            )
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "demo--1.0.sql",
                        "template": "demo.sql.in",
                        "substitutions": {"TOKEN": "reviewed"},
                        "inputs": [
                            {
                                "path": "demo.sql.in",
                                "sha256": _digest(template),
                            }
                        ],
                    }
                ],
            )

            report = scan_path(
                root,
                generation_plan=load_generation_plan(plan_path),
            )

        copy_findings = [
            finding
            for finding in report.findings
            if finding.rule_id == "sql.copy-program"
        ]
        self.assertEqual(1, len(copy_findings))
        self.assertEqual("demo--1.0.sql", copy_findings[0].path)

    def test_input_digest_mismatch_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "demo.control").write_text(
                "default_version = '1.0'\n",
                encoding="utf-8",
            )
            makefile = root / "Makefile"
            makefile.write_text("all:\n", encoding="utf-8")
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "demo--1.0.sql",
                        "inputs": [
                            {
                                "path": "Makefile",
                                "sha256": "sha256:" + "0" * 64,
                            }
                        ],
                    }
                ],
            )
            plan = load_generation_plan(plan_path)

            with self.assertRaisesRegex(ScanInputError, "digest mismatch"):
                scan_path(root, generation_plan=plan)

    def test_missing_substitution_token_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "demo.control.in"
            template.write_text(
                "default_version = '1.0'\n",
                encoding="utf-8",
            )
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "demo.control",
                        "template": "demo.control.in",
                        "substitutions": {"EXTVERSION": "1.0"},
                        "inputs": [
                            {
                                "path": "demo.control.in",
                                "sha256": _digest(template),
                            }
                        ],
                    }
                ],
            )

            with self.assertRaisesRegex(ScanInputError, "does not contain token"):
                scan_path(
                    root,
                    generation_plan=load_generation_plan(plan_path),
                )

    def test_rendered_expansion_limit_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "demo.control.in"
            template.write_text(
                "default_version = 'TOKEN TOKEN TOKEN TOKEN'\n",
                encoding="utf-8",
            )
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "demo.control",
                        "template": "demo.control.in",
                        "substitutions": {"TOKEN": "1234567890"},
                        "inputs": [
                            {
                                "path": "demo.control.in",
                                "sha256": _digest(template),
                            }
                        ],
                    }
                ],
            )

            with (
                patch.object(generation, "MAX_RENDERED_FILE_BYTES", 32),
                self.assertRaisesRegex(ScanInputError, "byte limit"),
            ):
                scan_path(
                    root,
                    generation_plan=load_generation_plan(plan_path),
                )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            path.write_text(
                '{"schema_version":"1.0","schema_version":"1.0",'
                '"artifacts":[]}\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(GenerationPlanError, "duplicate JSON"):
                load_generation_plan(path)

    def test_control_declaration_requires_template(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "Makefile"
            source.write_text("all:\n", encoding="utf-8")
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "demo.control",
                        "inputs": [
                            {
                                "path": "Makefile",
                                "sha256": _digest(source),
                            }
                        ],
                    }
                ],
            )

            with self.assertRaisesRegex(
                GenerationPlanError,
                "requires a template",
            ):
                load_generation_plan(plan_path)

    def test_parent_traversal_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "../demo.sql",
                        "inputs": [
                            {
                                "path": "Makefile",
                                "sha256": "sha256:" + "0" * 64,
                            }
                        ],
                    }
                ],
            )

            with self.assertRaisesRegex(GenerationPlanError, "scan root"):
                load_generation_plan(plan_path)

    def test_generated_target_collision_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "demo--1.0.sql"
            target.write_text("SELECT 1;\n", encoding="utf-8")
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "demo--1.0.sql",
                        "inputs": [
                            {
                                "path": "demo--1.0.sql",
                                "sha256": _digest(target),
                            }
                        ],
                    }
                ],
            )

            with self.assertRaisesRegex(ScanInputError, "conflicts"):
                scan_path(
                    root,
                    generation_plan=load_generation_plan(plan_path),
                )

    def test_generation_plan_requires_directory_scan(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "demo.sql"
            target.write_text("SELECT 1;\n", encoding="utf-8")
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "demo--1.0.sql",
                        "inputs": [
                            {
                                "path": "demo.sql",
                                "sha256": _digest(target),
                            }
                        ],
                    }
                ],
            )

            with self.assertRaisesRegex(ScanInputError, "directory"):
                scan_path(
                    target,
                    generation_plan=load_generation_plan(plan_path),
                )

    @unittest.skipUnless(hasattr(os, "symlink"), "requires filesystem symlinks")
    def test_symlinked_plan_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text(
                '{"schema_version":"1.0","artifacts":[]}\n',
                encoding="utf-8",
            )
            alias = root / "alias.json"
            alias.symlink_to(target.name)

            with self.assertRaisesRegex(GenerationPlanError, "symlink"):
                load_generation_plan(alias)

    def test_cli_rejects_invalid_plan_without_traceback(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text("SELECT 1;\n", encoding="utf-8")
            plan = root / "invalid.json"
            plan.write_text('{"schema_version": "unknown"}\n', encoding="utf-8")

            result = run_cli(
                "scan",
                str(source),
                "--generation-plan",
                str(plan),
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("generation plan", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_and_grouped_report_bind_generation_metadata(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "demo.control").write_text(
                "default_version = '1.0'\nsuperuser = false\n",
                encoding="utf-8",
            )
            makefile = root / "Makefile"
            makefile.write_text("all: demo--1.0.sql\n", encoding="utf-8")
            plan_path = _write_plan(
                root,
                [
                    {
                        "path": "demo--1.0.sql",
                        "inputs": [
                            {
                                "path": "Makefile",
                                "sha256": _digest(makefile),
                            }
                        ],
                    }
                ],
            )

            result = run_cli(
                "scan",
                str(root),
                "--format",
                "json",
                "--generation-plan",
                str(plan_path),
            )
            report = scan_path(
                root,
                generation_plan=load_generation_plan(plan_path),
            )
            grouped = grouped_report_document(report)
            text = render_text(report)
            sarif = to_sarif(report)

        self.assertEqual(0, result.returncode, result.stderr)
        document = parse_json_stdout(result)
        self.assertEqual("1.1", document["schema_version"])
        self.assertIn("generation", document)
        self.assertEqual(
            report.generation,
            grouped["generation"],
        )
        self.assertEqual("1.1", grouped["source_report_schema_version"])
        assert report.generation is not None
        plan_digest = report.generation["plan"]["digest"]
        self.assertIn(plan_digest, text)
        sarif_properties = sarif["runs"][0]["properties"]
        self.assertEqual(
            plan_digest,
            sarif_properties["generationPlanDigest"],
        )
        self.assertEqual(1, sarif_properties["generatedArtifacts"])


if __name__ == "__main__":
    unittest.main()
