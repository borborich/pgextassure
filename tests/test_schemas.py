"""Checks for the published machine-readable contracts."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.evidence import verify_evidence_bundle
from pgextassure.grouping import grouped_report_document
from pgextassure.review import review_pack_document
from pgextassure.scanner import scan_path
from tests.support import SAFE_ROOT, run_cli


SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schemas"


class PublishedSchemaTests(unittest.TestCase):
    def test_all_schema_files_are_unique_draft_2020_12_documents(self) -> None:
        identifiers: set[str] = set()
        schemas = sorted(SCHEMA_ROOT.glob("*.schema.json"))
        self.assertEqual(8, len(schemas))
        for path in schemas:
            with self.subTest(path=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(
                    "https://json-schema.org/draft/2020-12/schema",
                    document["$schema"],
                )
                self.assertNotIn(document["$id"], identifiers)
                identifiers.add(document["$id"])
                self.assertEqual("object", document["type"])

    def test_current_output_versions_have_published_schemas(self) -> None:
        report = scan_path(SAFE_ROOT)
        grouped = grouped_report_document(report)
        review_pack = review_pack_document(report)

        scan_schema = json.loads(
            (
                SCHEMA_ROOT
                / f"scan-report-{report.schema_version}.schema.json"
            ).read_text(encoding="utf-8")
        )
        grouped_schema = json.loads(
            (
                SCHEMA_ROOT
                / f"grouped-report-{grouped['schema_version']}.schema.json"
            ).read_text(encoding="utf-8")
        )
        review_schema = json.loads(
            (
                SCHEMA_ROOT
                / (
                    "agent-review-pack-"
                    f"{review_pack['schema_version']}.schema.json"
                )
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(
            report.schema_version,
            scan_schema["properties"]["schema_version"]["const"],
        )
        self.assertEqual(
            grouped["schema_version"],
            grouped_schema["properties"]["schema_version"]["const"],
        )
        self.assertTrue(
            set(scan_schema["required"]).issubset(report.to_dict())
        )
        self.assertTrue(
            set(grouped_schema["required"]).issubset(grouped)
        )
        self.assertEqual(
            review_pack["schema_version"],
            review_schema["properties"]["schema_version"]["const"],
        )
        self.assertTrue(
            set(review_schema["required"]).issubset(review_pack)
        )

    def test_evidence_bundle_index_has_a_published_schema(self) -> None:
        with TemporaryDirectory() as directory:
            bundle = Path(directory) / "evidence.zip"
            result = run_cli(
                "evidence",
                "create",
                str(SAFE_ROOT),
                "--created-on",
                "2026-07-29",
                "--output",
                str(bundle),
            )
            verification = verify_evidence_bundle(bundle)
            schema = json.loads(
                (
                    SCHEMA_ROOT / "evidence-bundle-1.0.schema.json"
                ).read_text(encoding="utf-8")
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            verification.predicate["schema_version"],
            schema["properties"]["schema_version"]["const"],
        )
        self.assertTrue(
            set(schema["required"]).issubset(verification.predicate)
        )


if __name__ == "__main__":
    unittest.main()
