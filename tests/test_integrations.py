"""Credential-free enterprise integration projection contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.enterprise import _json_bytes
from tests.support import run_cli


class EnterpriseIntegrationProjectionTests(unittest.TestCase):
    def _event(self, root: Path) -> Path:
        core = {
            "schema_version": "1.0",
            "event_type": "pgextassure.enterprise-admission-event",
            "observed_on": "2026-07-29",
            "outcome": "allow",
            "active": True,
            "request": {
                "id": "CHG-2026-0042",
                "target": "postgresql-prod/extension-slot-01",
                "evaluated_on": "2026-07-29",
            },
            "package": {
                "digest": "sha256:" + "1" * 64,
                "manifest_digest": "sha256:" + "2" * 64,
                "files": 17,
            },
            "decision": {
                "result": "admit",
                "reasons": [],
                "valid_until": "2026-08-05",
            },
            "trust": {
                "policy_id": "acme/postgresql-production",
                "policy_digest": "sha256:" + "3" * 64,
            },
            "subject": {
                "digest": "sha256:" + "4" * 64,
                "gate": "pass",
                "component": {
                    "name": "reference-extension",
                    "version": "1.0.0",
                },
                "tool": {
                    "name": "pgextassure",
                    "version": "0.1.0-alpha.14",
                    "ruleset_version": "2026-07-29.6",
                },
            },
            "signature": {
                "signer_id": "acme/key-01",
                "public_key_sha256": "sha256:" + "5" * 64,
                "created_on": "2026-07-29",
            },
        }
        event_id = "sha256:" + hashlib.sha256(_json_bytes(core)).hexdigest()
        path = root / "admission-event.json"
        path.write_bytes(_json_bytes({**core, "id": event_id}))
        return path

    def test_jira_cloud_payload_uses_adf_and_retains_exact_event(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            event_path = self._event(root)
            result = run_cli(
                "integration",
                "export",
                str(event_path),
                "--profile",
                "jira-cloud-v3",
                "--project",
                "SEC",
                "--issue-type",
                "Security Review",
            )
            source = json.loads(event_path.read_text(encoding="utf-8"))
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual({"key": "SEC"}, payload["fields"]["project"])
        self.assertEqual(
            "Security Review",
            payload["fields"]["issuetype"]["name"],
        )
        self.assertEqual("doc", payload["fields"]["description"]["type"])
        self.assertEqual(
            source,
            payload["properties"][0]["value"],
        )

    def test_servicenow_and_splunk_payloads_are_directly_serializable(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            event_path = self._event(root)
            snow = run_cli(
                "integration",
                "export",
                str(event_path),
                "--profile",
                "servicenow-change",
                "--table",
                "change_request",
            )
            splunk = run_cli(
                "integration",
                "export",
                str(event_path),
                "--profile",
                "splunk-hec",
                "--index",
                "security_events",
            )
        self.assertEqual(0, snow.returncode, snow.stderr)
        self.assertEqual(0, splunk.returncode, splunk.stderr)
        snow_payload = json.loads(snow.stdout)
        splunk_payload = json.loads(splunk.stdout)
        self.assertTrue(
            snow_payload["correlation_id"].startswith("sha256:")
        )
        self.assertIn("Canonical PgExtAssure", snow_payload["work_notes"])
        self.assertEqual("security_events", splunk_payload["index"])
        self.assertEqual(
            "pgextassure:admission",
            splunk_payload["sourcetype"],
        )
        self.assertEqual("allow", splunk_payload["event"]["outcome"])

    def test_elastic_bulk_is_canonical_two_line_ndjson(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            event_path = self._event(root)
            output = root / "elastic.ndjson"
            manifest_path = root / "elastic-export.json"
            result = run_cli(
                "integration",
                "export",
                str(event_path),
                "--profile",
                "elastic-bulk",
                "--index",
                "pgextassure-admission",
                "--output",
                str(output),
                "--manifest-output",
                str(manifest_path),
            )
            raw = output.read_text(encoding="utf-8")
            manifest_raw = manifest_path.read_bytes()
            manifest = json.loads(manifest_raw)
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas"
                    / "integration-export-1.0.schema.json"
                ).read_text(encoding="utf-8")
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(raw.endswith("\n"))
        lines = raw.splitlines()
        self.assertEqual(2, len(lines))
        action = json.loads(lines[0])
        document = json.loads(lines[1])
        self.assertEqual(
            "pgextassure-admission",
            action["index"]["_index"],
        )
        self.assertEqual(
            document["pgextassure"]["id"].removeprefix("sha256:"),
            action["index"]["_id"],
        )
        self.assertEqual("2026-07-29T00:00:00Z", document["@timestamp"])
        self.assertEqual(set(schema["required"]), set(manifest))
        self.assertEqual("elastic-bulk", manifest["profile"])
        self.assertEqual("/_bulk", manifest["request"]["path"])
        self.assertEqual(
            "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            manifest["payload"]["sha256"],
        )
        self.assertEqual(len(raw.encode("utf-8")), manifest["payload"]["size"])

    def test_tamper_duplicate_keys_and_invalid_vendor_inputs_fail_closed(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            event_path = self._event(root)
            event = json.loads(event_path.read_text(encoding="utf-8"))
            event["outcome"] = "deny"
            event_path.write_bytes(_json_bytes(event))
            tampered = run_cli(
                "integration",
                "export",
                str(event_path),
                "--profile",
                "splunk-hec",
            )
            event_path.write_text(
                '{"schema_version":"1.0","schema_version":"1.0"}\n',
                encoding="utf-8",
            )
            duplicate = run_cli(
                "integration",
                "export",
                str(event_path),
                "--profile",
                "splunk-hec",
            )
            valid_path = self._event(root)
            bad_project = run_cli(
                "integration",
                "export",
                str(valid_path),
                "--profile",
                "jira-cloud-v3",
                "--project",
                "../SEC",
            )
            bad_index = run_cli(
                "integration",
                "export",
                str(valid_path),
                "--profile",
                "elastic-bulk",
                "--index",
                "_system",
            )
        self.assertEqual(3, tampered.returncode)
        self.assertIn("active and outcome disagree", tampered.stderr)
        self.assertEqual(3, duplicate.returncode)
        self.assertIn("duplicate JSON key", duplicate.stderr)
        self.assertEqual(2, bad_project.returncode)
        self.assertIn("project key is invalid", bad_project.stderr)
        self.assertEqual(2, bad_index.returncode)
        self.assertIn("Elastic index is invalid", bad_index.stderr)


if __name__ == "__main__":
    unittest.main()
