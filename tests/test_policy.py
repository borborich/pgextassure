"""Contract tests for organization-owned admission gates."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.scanner import RULESET_VERSION
from tests.support import (
    FIXTURES_ROOT,
    VULNERABLE_ROOT,
    parse_json_stdout,
    run_cli,
)


def _policy(
    path: Path,
    *,
    minimum_severity: str = "high",
    blocked_capabilities: list[str] | None = None,
    blocked_rules: list[str] | None = None,
    maximum_skipped_files: int | None = 100_000,
    allow_baseline: bool = True,
    allow_suppressions: bool = True,
    require_ticket: bool = False,
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "ruleset_version": RULESET_VERSION,
                "gate": {
                    "minimum_severity": minimum_severity,
                    "blocked_capabilities": blocked_capabilities or [],
                    "blocked_rules": blocked_rules or [],
                    "maximum_skipped_files": maximum_skipped_files,
                },
                "admission": {
                    "allow_baseline": allow_baseline,
                    "allow_suppressions": allow_suppressions,
                    "require_suppression_ticket": require_ticket,
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


class OrganizationPolicyTests(unittest.TestCase):
    def test_policy_owns_gate_and_is_embedded_with_digest(self) -> None:
        with TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            _policy(policy, minimum_severity="critical")

            result = run_cli(
                "scan",
                str(VULNERABLE_ROOT / "sql" / "public_execute.sql"),
                "--format",
                "json",
                "--policy",
                str(policy),
            )

        self.assertEqual(0, result.returncode, result.stderr)
        document = parse_json_stdout(result)
        self.assertEqual(0, document["policy"]["result"]["blocked_count"])
        self.assertRegex(
            document["policy"]["digest"],
            r"^sha256:[0-9a-f]{64}$",
        )

    def test_policy_can_block_a_capability_below_severity_threshold(self) -> None:
        with TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            _policy(
                policy,
                minimum_severity="none",
                blocked_capabilities=["process.execute"],
            )

            result = run_cli(
                "scan",
                str(VULNERABLE_ROOT),
                "--format",
                "json",
                "--policy",
                str(policy),
            )

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertGreater(
            parse_json_stdout(result)["policy"]["result"]["blocked_count"],
            0,
        )

    def test_policy_and_fail_on_are_rejected_as_ambiguous(self) -> None:
        with TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            _policy(policy)
            result = run_cli(
                "scan",
                str(VULNERABLE_ROOT),
                "--policy",
                str(policy),
                "--fail-on",
                "high",
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("policy owns the gate", result.stderr)

    def test_policy_can_fail_on_any_skipped_file(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.sql").write_text("SELECT 1;\n", encoding="utf-8")
            (root / "README.md").write_text("review me\n", encoding="utf-8")
            policy = root / "policy.json"
            _policy(
                policy,
                minimum_severity="none",
                maximum_skipped_files=0,
            )

            result = run_cli(
                "scan",
                str(root),
                "--format",
                "json",
                "--policy",
                str(policy),
            )

        self.assertEqual(1, result.returncode, result.stderr)
        policy_result = parse_json_stdout(result)["policy"]["result"]
        self.assertTrue(policy_result["blocked"])
        self.assertTrue(policy_result["coverage_violation"])
        self.assertEqual(2, policy_result["skipped_count"])

    def test_policy_is_closed_schema_and_ruleset_bound(self) -> None:
        with TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            _policy(policy)
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["unexpected"] = True
            policy.write_text(json.dumps(document), encoding="utf-8")
            unknown = run_cli(
                "scan",
                str(VULNERABLE_ROOT),
                "--policy",
                str(policy),
            )

            _policy(policy)
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["ruleset_version"] = "stale"
            policy.write_text(json.dumps(document), encoding="utf-8")
            stale = run_cli(
                "scan",
                str(VULNERABLE_ROOT),
                "--policy",
                str(policy),
            )

        self.assertEqual(2, unknown.returncode)
        self.assertIn("unknown field", unknown.stderr)
        self.assertEqual(2, stale.returncode)
        self.assertIn("does not match", stale.stderr)

    def test_policy_can_prohibit_baselines(self) -> None:
        with TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            _policy(policy, allow_baseline=False)
            result = run_cli(
                "scan",
                str(FIXTURES_ROOT / "admission"),
                "--baseline",
                str(FIXTURES_ROOT / "admission" / "baseline.json"),
                "--policy",
                str(policy),
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("does not allow baselines", result.stderr)

    def test_policy_can_require_suppression_tickets(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            suppressions = root / "suppressions.json"
            _policy(policy, require_ticket=True)
            document = json.loads(
                (
                    FIXTURES_ROOT / "admission" / "suppressions.json"
                ).read_text(encoding="utf-8")
            )
            del document["suppressions"][0]["ticket"]
            suppressions.write_text(json.dumps(document), encoding="utf-8")

            result = run_cli(
                "scan",
                str(FIXTURES_ROOT / "admission"),
                "--suppressions",
                str(suppressions),
                "--evaluated-on",
                "2026-07-29",
                "--policy",
                str(policy),
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("requires a ticket", result.stderr)


if __name__ == "__main__":
    unittest.main()
