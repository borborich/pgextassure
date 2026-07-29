"""Contract tests for conservative root-cause grouping."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.grouping import group_findings, grouped_report_document
from pgextassure.models import Finding, Severity
from pgextassure.reporting import render_grouped_json
from pgextassure.scanner import scan_path
from tests.support import parse_json_stdout, run_cli


def _finding(
    *,
    path: str,
    line: int,
    evidence: str,
    rule_id: str = "sql.security-definer-public-execute",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="Privileged routine is public",
        message="Review the routine.",
        path=path,
        line=line,
        evidence=evidence,
        capability="database.public-execute",
        remediation="Revoke PUBLIC execution.",
    )


class RootCauseGroupingTests(unittest.TestCase):
    def test_versioned_routine_occurrences_share_one_root_cause(self) -> None:
        identity = "routine = function public.lookup_secret(secret_id bigint)"
        groups = group_findings(
            (
                _finding(
                    path="sql/updates/demo--1.0--1.1.sql",
                    line=10,
                    evidence=identity,
                ),
                _finding(
                    path="sql/demo--1.1.sql",
                    line=20,
                    evidence=identity,
                ),
            )
        )

        self.assertEqual(1, len(groups))
        self.assertEqual("demo", groups[0].scope)
        self.assertEqual(identity, groups[0].identity)
        self.assertEqual(2, groups[0].occurrence_count)
        self.assertRegex(groups[0].root_cause_id, r"^sha256:[0-9a-f]{64}$")
        first_id = group_findings(
            (
                _finding(
                    path="sql/updates/demo--1.0--1.1.sql",
                    line=10,
                    evidence=identity,
                ),
            )
        )[0].root_cause_id
        moved_id = group_findings(
            (
                _finding(
                    path="sql/demo--1.1.sql",
                    line=200,
                    evidence=identity,
                ),
            )
        )[0].root_cause_id
        self.assertEqual(first_id, moved_id)

    def test_same_routine_name_in_different_packages_is_not_merged(self) -> None:
        identity = "routine = function public.lookup_secret(bigint)"
        groups = group_findings(
            (
                _finding(
                    path="extension-a/sql/demo--1.0.sql",
                    line=10,
                    evidence=identity,
                ),
                _finding(
                    path="extension-b/sql/demo--1.0.sql",
                    line=10,
                    evidence=identity,
                ),
            )
        )

        self.assertEqual(2, len(groups))
        self.assertEqual(
            {"extension-a/demo", "extension-b/demo"},
            {group.scope for group in groups},
        )

    def test_rules_without_semantic_identity_remain_location_scoped(self) -> None:
        groups = group_findings(
            (
                _finding(
                    rule_id="sql.external-connection",
                    path="sql/demo--1.0.sql",
                    line=10,
                    evidence="http_get(...)",
                ),
                _finding(
                    rule_id="sql.external-connection",
                    path="sql/demo--1.1.sql",
                    line=20,
                    evidence="http_get(...)",
                ),
            )
        )

        self.assertEqual(2, len(groups))
        self.assertEqual({1}, {group.occurrence_count for group in groups})

    def test_grouped_document_counts_findings_and_root_causes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("demo--1.0--1.1.sql", "demo--1.1--1.2.sql"):
                (root / name).write_text(
                    "CREATE FUNCTION public.lookup_secret(secret_id bigint) "
                    "RETURNS bigint LANGUAGE sql SECURITY DEFINER "
                    "AS $$ SELECT secret_id $$;\n",
                    encoding="utf-8",
                )

            report = scan_path(root)
            document = grouped_report_document(report)

        self.assertEqual("1.3", document["schema_version"])
        self.assertEqual(
            "pgextassure.root-cause-groups",
            document["report_type"],
        )
        self.assertEqual(4, document["summary"]["findings"])
        self.assertEqual(2, document["summary"]["root_causes"])
        self.assertEqual(2, len(document["root_causes"]))
        self.assertEqual(
            {2},
            {
                group["occurrence_count"]
                for group in document["root_causes"]
            },
        )

    def test_grouped_json_is_byte_deterministic(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                "CREATE FUNCTION public.lookup_secret(secret_id bigint) "
                "RETURNS bigint LANGUAGE sql SECURITY DEFINER "
                "AS $$ SELECT secret_id $$;\n",
                encoding="utf-8",
            )
            report = scan_path(path)

            first = render_grouped_json(report)
            second = render_grouped_json(report)

        self.assertEqual(first, second)
        self.assertEqual(
            "pgextassure.root-cause-groups",
            json.loads(first)["report_type"],
        )

    def test_cli_exposes_grouped_json_without_changing_json_v1(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                "CREATE FUNCTION public.lookup_secret(secret_id bigint) "
                "RETURNS bigint LANGUAGE sql SECURITY DEFINER "
                "AS $$ SELECT secret_id $$;\n",
                encoding="utf-8",
            )

            grouped = run_cli(
                "scan",
                str(path),
                "--format",
                "grouped-json",
            )
            original = run_cli("scan", str(path), "--format", "json")

        self.assertEqual(0, grouped.returncode, grouped.stderr)
        self.assertEqual(0, original.returncode, original.stderr)
        grouped_document = parse_json_stdout(grouped)
        original_document = parse_json_stdout(original)
        self.assertIn("root_causes", grouped_document)
        self.assertNotIn("findings", grouped_document)
        self.assertIn("findings", original_document)
        self.assertNotIn("root_causes", original_document)


if __name__ == "__main__":
    unittest.main()
