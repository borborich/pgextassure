"""Contract tests for baselines and expiring review suppressions."""

from __future__ import annotations

from datetime import date
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.admission import (
    AdmissionError,
    apply_admission,
    create_baseline_document,
    load_baseline,
    load_suppressions,
)
from pgextassure.grouping import group_findings, grouped_report_document
from pgextassure.reporting import render_text, to_sarif
from pgextassure.scanner import RULESET_VERSION, scan_path
from tests.support import parse_json_stdout, run_cli


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _suppression_document(
    root_cause_id: str,
    rule_id: str,
    severity: str,
    *,
    expires_on: str = "2026-07-29",
    ruleset_version: str = RULESET_VERSION,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "ruleset_version": ruleset_version,
        "suppressions": [
            {
                "root_cause_id": root_cause_id,
                "rule_id": rule_id,
                "severity": severity,
                "owner": "database-platform",
                "reason": "Accepted temporarily while remediation is reviewed.",
                "expires_on": expires_on,
                "ticket": "SEC-123",
            }
        ],
    }


class AdmissionStateTests(unittest.TestCase):
    def test_baseline_command_preserves_findings_and_unblocks_known_roots(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            baseline_path = root / "baseline.json"
            created = run_cli(
                "baseline",
                str(source),
                "--created-on",
                "2026-07-29",
                "--output",
                str(baseline_path),
            )
            scanned = run_cli(
                "scan",
                str(source),
                "--baseline",
                str(baseline_path),
                "--format",
                "json",
                "--fail-on",
                "high",
            )
            baseline_text = baseline_path.read_text(encoding="utf-8")

        self.assertEqual(0, created.returncode, created.stderr)
        self.assertEqual(0, scanned.returncode, scanned.stderr)
        document = parse_json_stdout(scanned)
        self.assertEqual("1.4", document["schema_version"])
        self.assertTrue(document["findings"])
        self.assertEqual(
            len(document["findings"]),
            document["summary"]["findings"],
        )
        self.assertEqual(
            1,
            document["admission"]["summary"]["baselined"],
        )
        self.assertEqual(
            "baselined",
            document["admission"]["decisions"][0]["status"],
        )
        self.assertNotIn("PROGRAM", baseline_text)
        self.assertNotIn("Evidence", baseline_text)

    def test_new_root_cause_still_blocks_with_a_baseline(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            baseline_path = root / "baseline.json"
            created = run_cli(
                "baseline",
                str(source),
                "--created-on",
                "2026-07-29",
                "--output",
                str(baseline_path),
            )
            self.assertEqual(0, created.returncode, created.stderr)
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n"
                "COPY demo TO '/tmp/export';\n",
                encoding="utf-8",
            )

            scanned = run_cli(
                "scan",
                str(source),
                "--baseline",
                str(baseline_path),
                "--format",
                "json",
                "--fail-on",
                "high",
            )

        self.assertEqual(1, scanned.returncode, scanned.stderr)
        admission = parse_json_stdout(scanned)["admission"]
        self.assertEqual(1, admission["summary"]["baselined"])
        self.assertEqual(1, admission["summary"]["active"])

    def test_suppression_is_inclusive_on_expiry_and_then_blocks(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            group = group_findings(scan_path(source).findings)[0]
            suppressions_path = root / "suppressions.json"
            _write_json(
                suppressions_path,
                _suppression_document(
                    group.root_cause_id,
                    group.rule_id,
                    group.severity.value,
                ),
            )

            active = run_cli(
                "scan",
                str(source),
                "--suppressions",
                str(suppressions_path),
                "--evaluated-on",
                "2026-07-29",
                "--format",
                "json",
                "--fail-on",
                "critical",
            )
            expired = run_cli(
                "scan",
                str(source),
                "--suppressions",
                str(suppressions_path),
                "--evaluated-on",
                "2026-07-30",
                "--format",
                "json",
                "--fail-on",
                "critical",
            )

        self.assertEqual(0, active.returncode, active.stderr)
        self.assertEqual(1, expired.returncode, expired.stderr)
        active_document = parse_json_stdout(active)
        expired_document = parse_json_stdout(expired)
        self.assertTrue(active_document["findings"])
        self.assertEqual(
            "suppressed",
            active_document["admission"]["decisions"][0]["status"],
        )
        self.assertEqual(
            "expired",
            expired_document["admission"]["decisions"][0]["status"],
        )
        self.assertEqual(
            "database-platform",
            expired_document["admission"]["decisions"][0]["owner"],
        )

    def test_admission_metadata_reaches_grouped_sarif_and_text(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            original = scan_path(source)
            group = group_findings(original.findings)[0]
            suppression_path = root / "suppressions.json"
            _write_json(
                suppression_path,
                _suppression_document(
                    group.root_cause_id,
                    group.rule_id,
                    group.severity.value,
                ),
            )
            report = apply_admission(
                original,
                suppressions=load_suppressions(suppression_path),
                evaluated_on=date(2026, 7, 29),
            )

        grouped = grouped_report_document(report)
        sarif = to_sarif(report)
        text = render_text(report)
        self.assertEqual("1.3", grouped["schema_version"])
        self.assertEqual(
            "suppressed",
            grouped["root_causes"][0]["admission"]["status"],
        )
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(
            "suppressed",
            result["properties"]["admissionStatus"],
        )
        self.assertEqual("accepted", result["suppressions"][0]["status"])
        self.assertEqual(
            report.admission["suppressions"]["digest"],
            sarif["runs"][0]["properties"]["suppressionsDigest"],
        )
        self.assertIn("[SUPPRESSED]", text)
        self.assertIn("database-platform", text)

    def test_ruleset_mismatch_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            group = group_findings(scan_path(source).findings)[0]
            suppression_path = root / "suppressions.json"
            _write_json(
                suppression_path,
                _suppression_document(
                    group.root_cause_id,
                    group.rule_id,
                    group.severity.value,
                    ruleset_version="stale-ruleset",
                ),
            )

            result = run_cli(
                "scan",
                str(source),
                "--suppressions",
                str(suppression_path),
                "--evaluated-on",
                "2026-07-29",
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("ruleset_version", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_baseline_ruleset_mismatch_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            document = create_baseline_document(
                scan_path(source),
                created_on=date(2026, 7, 29),
            )
            document["tool"]["ruleset_version"] = "stale-ruleset"
            baseline_path = root / "baseline.json"
            _write_json(baseline_path, document)

            result = run_cli(
                "scan",
                str(source),
                "--baseline",
                str(baseline_path),
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("ruleset_version", result.stderr)

    def test_evaluation_date_without_suppressions_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            source = Path(temporary) / "demo.sql"
            source.write_text("SELECT 1;\n", encoding="utf-8")

            result = run_cli(
                "scan",
                str(source),
                "--evaluated-on",
                "2026-07-29",
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("requires --suppressions", result.stderr)

    def test_matching_id_with_wrong_metadata_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            group = group_findings(scan_path(source).findings)[0]
            suppression_path = root / "suppressions.json"
            _write_json(
                suppression_path,
                _suppression_document(
                    group.root_cause_id,
                    "sql.copy-server-file",
                    group.severity.value,
                ),
            )

            result = run_cli(
                "scan",
                str(source),
                "--suppressions",
                str(suppression_path),
                "--evaluated-on",
                "2026-07-29",
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("metadata does not match", result.stderr)

    def test_baseline_and_suppression_overlap_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            report = scan_path(source)
            group = group_findings(report.findings)[0]
            baseline_path = root / "baseline.json"
            _write_json(
                baseline_path,
                create_baseline_document(
                    report,
                    created_on=date(2026, 7, 29),
                ),
            )
            suppression_path = root / "suppressions.json"
            _write_json(
                suppression_path,
                _suppression_document(
                    group.root_cause_id,
                    group.rule_id,
                    group.severity.value,
                ),
            )

            result = run_cli(
                "scan",
                str(source),
                "--baseline",
                str(baseline_path),
                "--suppressions",
                str(suppression_path),
                "--evaluated-on",
                "2026-07-29",
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("overlap", result.stderr)

    def test_unused_suppression_is_reported_but_does_not_hide_findings(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            suppression_path = root / "suppressions.json"
            _write_json(
                suppression_path,
                _suppression_document(
                    "sha256:" + "0" * 64,
                    "sql.copy-program",
                    "critical",
                ),
            )

            result = run_cli(
                "scan",
                str(source),
                "--suppressions",
                str(suppression_path),
                "--evaluated-on",
                "2026-07-29",
                "--format",
                "json",
                "--fail-on",
                "critical",
            )

        self.assertEqual(1, result.returncode, result.stderr)
        document = parse_json_stdout(result)
        self.assertEqual(1, document["admission"]["summary"]["active"])
        self.assertEqual(1, document["admission"]["suppressions"]["unused"])

    def test_duplicate_keys_and_invalid_dates_are_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":"1.0","schema_version":"1.0",'
                '"ruleset_version":"x","suppressions":[]}\n',
                encoding="utf-8",
            )
            invalid_date = root / "date.json"
            _write_json(
                invalid_date,
                {
                    "schema_version": "1.0",
                    "ruleset_version": RULESET_VERSION,
                    "suppressions": [
                        {
                            "root_cause_id": "sha256:" + "0" * 64,
                            "rule_id": "sql.copy-program",
                            "severity": "critical",
                            "owner": "team",
                            "reason": "temporary",
                            "expires_on": "29-07-2026",
                        }
                    ],
                },
            )

            with self.assertRaisesRegex(AdmissionError, "duplicate JSON"):
                load_suppressions(duplicate)
            with self.assertRaisesRegex(AdmissionError, "ISO date"):
                load_suppressions(invalid_date)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires filesystem symlinks")
    def test_symlinked_admission_files_are_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "baseline.json"
            _write_json(
                target,
                {
                    "schema_version": "1.0",
                    "created_on": "2026-07-29",
                    "tool": {
                        "name": "pgextassure",
                        "version": "0.1.0-alpha.2",
                        "ruleset_version": RULESET_VERSION,
                    },
                    "source": {
                        "manifest_digest": "sha256:" + "0" * 64,
                    },
                    "root_causes": [],
                },
            )
            alias = root / "alias.json"
            alias.symlink_to(target.name)

            with self.assertRaisesRegex(AdmissionError, "symlink"):
                load_baseline(alias)

    def test_baseline_bytes_are_deterministic(self) -> None:
        with TemporaryDirectory() as temporary:
            source = Path(temporary) / "demo.sql"
            source.write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            first = run_cli(
                "baseline",
                str(source),
                "--created-on",
                "2026-07-29",
            )
            second = run_cli(
                "baseline",
                str(source),
                "--created-on",
                "2026-07-29",
            )

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(
            "1.0",
            json.loads(first.stdout)["schema_version"],
        )


if __name__ == "__main__":
    unittest.main()
