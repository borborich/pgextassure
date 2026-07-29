"""Tests for deterministic, authority-free agent review packs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.grouping import grouped_report_document
from pgextassure.review import (
    ReviewError,
    render_decision_template,
    render_review_pack,
    review_pack_document,
    verify_decision_ledger,
)
from pgextassure.scanner import scan_path
from pgextassure.source import canonical_json_bytes
from tests.support import VULNERABLE_ROOT, run_cli


class AgentReviewPackTests(unittest.TestCase):
    def test_pack_is_deterministic_and_binds_grouped_report(self) -> None:
        report = scan_path(VULNERABLE_ROOT)
        first = render_review_pack(report)
        second = render_review_pack(report)
        document = json.loads(first)
        expected_digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_json_bytes(grouped_report_document(report))
            ).hexdigest()
        )

        self.assertEqual(first, second)
        self.assertEqual(
            expected_digest,
            document["subject"]["grouped_report_digest"],
        )
        self.assertFalse(document["authority"]["can_grant_admission"])
        self.assertFalse(document["handling"]["contains_source_files"])
        self.assertEqual(
            document["summary"]["root_causes"],
            len(document["tasks"]),
        )
        self.assertTrue(document["tasks"])
        self.assertEqual(
            document["tasks"][0]["task_id"],
            document["tasks"][0]["root_cause"]["root_cause_id"],
        )

    def test_cli_writes_review_json_without_changing_gate(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "review.json"
            result = run_cli(
                "scan",
                str(VULNERABLE_ROOT),
                "--format",
                "review-json",
                "--fail-on",
                "high",
                "--output",
                str(output),
            )
            document = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual(
            "pgextassure.agent-review-pack",
            document["review_type"],
        )

    def test_review_document_does_not_embed_source_payloads(self) -> None:
        document = review_pack_document(scan_path(VULNERABLE_ROOT))
        rendered = json.dumps(document)

        self.assertNotIn("source_files", document)
        self.assertNotIn("CREATE FUNCTION", rendered)

    def test_decision_template_round_trips_offline(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pack = root / "review.json"
            ledger = root / "decisions.json"
            pack.write_text(
                render_review_pack(scan_path(VULNERABLE_ROOT)),
                encoding="utf-8",
            )
            first = render_decision_template(pack)
            second = render_decision_template(pack)
            ledger.write_text(first, encoding="utf-8")
            summary = verify_decision_ledger(pack, ledger)

        self.assertEqual(first, second)
        self.assertTrue(summary["valid"])
        self.assertFalse(summary["can_grant_admission"])
        self.assertEqual(
            summary["decisions"],
            summary["by_disposition"]["unresolved"],
        )

    def test_cli_creates_and_verifies_decision_ledger(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pack = root / "review.json"
            ledger = root / "decisions.json"
            pack.write_text(
                render_review_pack(scan_path(VULNERABLE_ROOT)),
                encoding="utf-8",
            )
            created = run_cli(
                "review",
                "template",
                str(pack),
                "--output",
                str(ledger),
            )
            verified = run_cli(
                "review",
                "verify",
                str(pack),
                str(ledger),
                "--format",
                "json",
            )
            summary = json.loads(verified.stdout)

        self.assertEqual(0, created.returncode, created.stderr)
        self.assertEqual(0, verified.returncode, verified.stderr)
        self.assertTrue(summary["valid"])
        self.assertFalse(summary["can_grant_admission"])

    def test_stale_pack_and_duplicate_task_decisions_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pack = root / "review.json"
            ledger = root / "decisions.json"
            pack.write_text(
                render_review_pack(scan_path(VULNERABLE_ROOT)),
                encoding="utf-8",
            )
            document = json.loads(render_decision_template(pack))
            document["review_pack_digest"] = "sha256:" + ("0" * 64)
            ledger.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ReviewError):
                verify_decision_ledger(pack, ledger)

            document = json.loads(render_decision_template(pack))
            if len(document["decisions"]) > 1:
                document["decisions"][1]["task_id"] = document["decisions"][0][
                    "task_id"
                ]
            ledger.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ReviewError):
                verify_decision_ledger(pack, ledger)

    def test_resolved_decision_requires_citations_and_reviewer(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pack = root / "review.json"
            ledger = root / "decisions.json"
            pack.write_text(
                render_review_pack(scan_path(VULNERABLE_ROOT)),
                encoding="utf-8",
            )
            document = json.loads(render_decision_template(pack))
            document["decisions"][0]["disposition"] = "accepted-capability"
            ledger.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaises(ReviewError):
                verify_decision_ledger(pack, ledger)

            document["decisions"][0].update(
                {
                    "rationale": "The cited control explicitly requires this capability.",
                    "citations": ["task root-cause location 1"],
                    "reviewer": "security-review-agent",
                }
            )
            ledger.write_text(json.dumps(document), encoding="utf-8")
            summary = verify_decision_ledger(pack, ledger)

        self.assertEqual(
            1,
            summary["by_disposition"]["accepted-capability"],
        )


if __name__ == "__main__":
    unittest.main()
