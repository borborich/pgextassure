"""Contract tests for the disclosure-safe public assurance index."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = PROJECT_ROOT / "tools" / "generate_assurance_index.py"
SPEC = importlib.util.spec_from_file_location(
    "pgextassure_public_assurance_index", GENERATOR_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import index generator from {GENERATOR_PATH}")
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)

COMMIT = "1" * 40
MANIFEST = (
    "repository\turl\tcommit\tcommit_date\tscan_path\tgeneration_plan\tscope_plan\n"
    "sample\thttps://github.com/example/sample.git\t"
    f"{COMMIT}\t2026-07-28\t.\t-\t-\n"
).encode()


def _summary(record: dict[str, object]) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": "1.0",
                "tool": {
                    "name": "pgextassure",
                    "version": "0.1.0-alpha.15",
                    "ruleset_version": "2026-07-28.2",
                },
                "corpus": [record],
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _record() -> dict[str, object]:
    return {
        "repository": "sample",
        "url": "https://github.com/example/sample.git",
        "commit": COMMIT,
        "commit_date": "2026-07-28",
        "scan_path": ".",
        "status": "ok",
        "source_manifest_digest": "sha256:" + ("2" * 64),
        "files_scanned": 12,
        "findings": 47,
        "root_causes": 5,
        "by_severity": {"critical": 4, "high": 9, "medium": 2, "low": 1},
        "rule_counts": {"sql.example": 47},
        "capabilities": ["network.client", "database.security-definer"],
    }


class PublicAssuranceIndexTests(unittest.TestCase):
    def test_output_is_deterministic_and_omits_finding_metadata(self) -> None:
        content = _summary(_record())
        first = GENERATOR.render_json(GENERATOR.build_index(content, MANIFEST))
        second = GENERATOR.render_json(GENERATOR.build_index(content, MANIFEST))

        self.assertEqual(first, second)
        document = json.loads(first)
        project = document["projects"][0]
        self.assertEqual("completed", project["analysis_status"])
        self.assertEqual(12, project["files_analyzed"])
        self.assertEqual(
            ["database.security-definer", "network.client"],
            project["capability_profile"],
        )
        serialized_project = json.dumps(project)
        for prohibited in (
            "findings",
            "root_causes",
            "by_severity",
            "rule_counts",
            "critical",
            "high",
            "evidence",
        ):
            self.assertNotIn(prohibited, serialized_project)
        self.assertTrue(document["notice"]["not_a_security_rating"])
        self.assertTrue(document["notice"]["not_a_certification"])

    def test_markdown_uses_neutral_analysis_status(self) -> None:
        document = GENERATOR.build_index(_summary(_record()), MANIFEST)
        markdown = GENERATOR.render_markdown(document)

        self.assertIn("Analysis", markdown)
        self.assertIn("completed", markdown)
        self.assertNotIn("passed", markdown.lower())
        self.assertNotIn("secure", markdown.lower())
        self.assertNotIn("critical", markdown.lower())

    def test_raw_finding_collection_is_rejected(self) -> None:
        record = _record()
        record["findings"] = [{"evidence": "secret source"}]

        with self.assertRaisesRegex(GENERATOR.IndexError, "raw record collection"):
            GENERATOR.build_index(_summary(record), MANIFEST)

    def test_manifest_mismatch_is_rejected(self) -> None:
        record = _record()
        record["commit"] = "3" * 40

        with self.assertRaisesRegex(GENERATOR.IndexError, "does not match manifest"):
            GENERATOR.build_index(_summary(record), MANIFEST)

    def test_tool_versions_cannot_inject_markdown(self) -> None:
        summary = json.loads(_summary(_record()))
        summary["tool"]["version"] = "0.1\n[link](https://example.invalid)"

        with self.assertRaisesRegex(GENERATOR.IndexError, "publication-safe"):
            GENERATOR.build_index(
                (json.dumps(summary) + "\n").encode(), MANIFEST
            )

    def test_manifest_cannot_claim_an_unrecorded_scope_plan(self) -> None:
        manifest = MANIFEST.replace(b"\t-\t-\n", b"\t-\tplans/scope.json\n")

        with self.assertRaisesRegex(GENERATOR.IndexError, "scope_plan"):
            GENERATOR.build_index(_summary(_record()), manifest)

    def test_non_completion_exposes_only_stable_class(self) -> None:
        record = _record()
        record = {
            key: value
            for key, value in record.items()
            if key
            not in {
                "source_manifest_digest",
                "files_scanned",
                "findings",
                "root_causes",
                "by_severity",
                "rule_counts",
                "capabilities",
            }
        }
        record.update(
            {
                "status": "scan_error",
                "error_code": "resource_limit",
                "error_type": "ScanInputError",
            }
        )

        document = GENERATOR.build_index(_summary(record), MANIFEST)
        project = document["projects"][0]

        self.assertEqual("not_completed", project["analysis_status"])
        self.assertEqual("resource_limit", project["non_completion_class"])
        self.assertNotIn("error_type", project)
        self.assertNotIn("files_analyzed", project)

    def test_generate_writes_json_and_markdown(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary = root / "summary.json"
            manifest = root / "manifest.tsv"
            output = root / "output"
            summary.write_bytes(_summary(_record()))
            manifest.write_bytes(MANIFEST)

            GENERATOR.generate(summary, manifest, output)

            self.assertTrue((output / "index.json").is_file())
            self.assertTrue((output / "index.md").is_file())

    def test_schema_has_status_specific_field_contracts(self) -> None:
        schema = json.loads(
            (
                PROJECT_ROOT
                / "schemas"
                / "public-assurance-index-1.0.schema.json"
            ).read_text(encoding="utf-8")
        )
        conditions = schema["properties"]["projects"]["items"]["allOf"]

        completed = conditions[0]["then"]
        not_completed = conditions[1]["then"]
        self.assertEqual(
            {"source_manifest_digest", "files_analyzed", "capability_profile"},
            set(completed["required"]),
        )
        self.assertEqual(["non_completion_class"], not_completed["required"])


if __name__ == "__main__":
    unittest.main()
