"""Tests for deterministic, authority-free agent review packs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.grouping import grouped_report_document
from pgextassure.review import render_review_pack, review_pack_document
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


if __name__ == "__main__":
    unittest.main()
