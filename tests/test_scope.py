"""Contracts for digest-bound scan roots and exact exclusions."""

from __future__ import annotations

from datetime import date
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.admission import create_baseline_document
from pgextassure.reporting import render_text, to_sarif
from pgextassure.scanner import ScanInputError, scan_path
from pgextassure.scope import ScopePlanError, load_scope_plan
from tests.support import run_cli


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _write_plan(
    root: Path,
    *,
    roots: list[str],
    exclusions: list[dict[str, str]],
) -> Path:
    path = root / "scope-plan.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "roots": roots,
                "exclusions": exclusions,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


class ScopePlanTests(unittest.TestCase):
    def test_multiple_roots_and_regular_exclusion_are_digest_bound(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            omitted = root / "omitted"
            first.mkdir()
            second.mkdir()
            omitted.mkdir()
            (first / "one.sql").write_text("SELECT 1;\n", encoding="utf-8")
            excluded = first / "large.sql"
            excluded.write_bytes(b"x" * 128)
            (second / "two.c").write_text("void demo(void) {}\n", encoding="utf-8")
            (omitted / "three.sql").write_text("SELECT 3;\n", encoding="utf-8")
            plan_path = _write_plan(
                root,
                roots=["first", "second"],
                exclusions=[
                    {
                        "path": "first/large.sql",
                        "kind": "regular",
                        "sha256": _sha256(excluded.read_bytes()),
                    }
                ],
            )

            plan = load_scope_plan(plan_path)
            report = scan_path(root, scope_plan=plan)

        self.assertEqual(["first/one.sql", "second/two.c"], [
            item.path for item in report.manifest.files
        ])
        self.assertEqual("1.4", report.schema_version)
        self.assertEqual(plan.digest, report.scope["plan"]["digest"])
        self.assertEqual("scope_excluded", report.coverage.skipped_files[0].reason)
        self.assertIn(plan.digest, render_text(report))
        self.assertEqual(
            plan.digest,
            to_sarif(report)["runs"][0]["properties"]["scopePlanDigest"],
        )
        self.assertEqual(
            plan.digest,
            create_baseline_document(
                report,
                created_on=date(2026, 7, 29),
            )["source"]["scope_plan_digest"],
        )

    def test_regular_exclusion_fails_after_content_change(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "safe.sql").write_text("SELECT 1;\n", encoding="utf-8")
            excluded = root / "excluded.sql"
            excluded.write_text("SELECT 2;\n", encoding="utf-8")
            plan = load_scope_plan(
                _write_plan(
                    root,
                    roots=["."],
                    exclusions=[
                        {
                            "path": "excluded.sql",
                            "kind": "regular",
                            "sha256": _sha256(excluded.read_bytes()),
                        }
                    ],
                )
            )
            excluded.write_text("SELECT 3;\n", encoding="utf-8")

            with self.assertRaisesRegex(ScanInputError, "digest mismatch"):
                scan_path(root, scope_plan=plan)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires filesystem symlinks")
    def test_symlink_exclusion_hashes_target_without_following(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "safe.sql").write_text("SELECT 1;\n", encoding="utf-8")
            outside = root / "outside.sql"
            outside.write_text("COPY x FROM PROGRAM 'id';\n", encoding="utf-8")
            alias = root / "alias.sql"
            alias.symlink_to("outside.sql")
            plan = load_scope_plan(
                _write_plan(
                    root,
                    roots=["."],
                    exclusions=[
                        {
                            "path": "alias.sql",
                            "kind": "symlink",
                            "sha256": _sha256(b"outside.sql"),
                        }
                    ],
                )
            )

            report = scan_path(root, scope_plan=plan)
            outside.write_text("changed but target spelling is stable\n", encoding="utf-8")
            second = scan_path(root, scope_plan=plan)

        self.assertEqual(report.scope, second.scope)
        self.assertNotIn("alias.sql", [item.path for item in report.manifest.files])

    def test_unused_exclusion_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "safe.sql").write_text("SELECT 1;\n", encoding="utf-8")
            plan = load_scope_plan(
                _write_plan(
                    root,
                    roots=["."],
                    exclusions=[
                        {
                            "path": "missing.sql",
                            "kind": "regular",
                            "sha256": _sha256(b""),
                        }
                    ],
                )
            )

            with self.assertRaisesRegex(ScanInputError, "unused scope exclusion"):
                scan_path(root, scope_plan=plan)

    def test_overlapping_roots_and_noncanonical_paths_are_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = _write_plan(root, roots=["pkg", "pkg/sql"], exclusions=[])
            with self.assertRaisesRegex(ScopePlanError, "must not overlap"):
                load_scope_plan(path)

            path = _write_plan(root, roots=["./pkg"], exclusions=[])
            with self.assertRaisesRegex(ScopePlanError, "canonical"):
                load_scope_plan(path)

    def test_cli_and_evidence_include_exact_scope_plan(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "safe.sql").write_text("SELECT 1;\n", encoding="utf-8")
            plan_path = _write_plan(root, roots=["."], exclusions=[])
            plan_bytes = plan_path.read_bytes()
            bundle = root / "evidence.zip"

            scan = run_cli(
                "scan",
                str(root),
                "--scope-plan",
                str(plan_path),
                "--format",
                "json",
            )
            evidence = run_cli(
                "evidence",
                "create",
                str(root),
                "--scope-plan",
                str(plan_path),
                "--created-on",
                "2026-07-29",
                "--output",
                str(bundle),
            )

            import zipfile

            with zipfile.ZipFile(bundle) as archive:
                packaged = archive.read("inputs/scope-plan.json")

        self.assertEqual(0, scan.returncode, scan.stderr)
        self.assertEqual(0, evidence.returncode, evidence.stderr)
        self.assertEqual(plan_bytes, packaged)


if __name__ == "__main__":
    unittest.main()
