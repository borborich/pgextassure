"""Evidence Bundle 1.0 creation and offline-verification contracts."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import warnings
import zipfile

from pgextassure.evidence import (
    EvidenceError,
    read_evidence_material,
    verify_evidence_bundle,
)
from tests.support import (
    FIXTURES_ROOT,
    SAFE_ROOT,
    VULNERABLE_ROOT,
    run_cli,
)


def _rewrite_zip(
    source: Path,
    destination: Path,
    *,
    replace: dict[str, bytes] | None = None,
    additions: list[tuple[str, bytes]] | None = None,
) -> None:
    replacements = replace or {}
    extra = additions or []
    with (
        zipfile.ZipFile(source) as original,
        zipfile.ZipFile(
            destination,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
        ) as modified,
    ):
        for info in original.infolist():
            modified.writestr(info.filename, replacements.get(
                info.filename,
                original.read(info),
            ))
        for name, raw in extra:
            modified.writestr(name, raw)


class EvidenceBundleTests(unittest.TestCase):
    def test_create_is_deterministic_and_verify_is_offline(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.zip"
            second = root / "second.zip"
            arguments = (
                "evidence",
                "create",
                str(SAFE_ROOT),
                "--created-on",
                "2026-07-29",
                "--component-name",
                "safe_extension",
                "--component-version",
                "2.0",
            )

            first_result = run_cli(*arguments, "--output", str(first))
            second_result = run_cli(*arguments, "--output", str(second))
            verification = run_cli(
                "evidence",
                "verify",
                str(first),
                "--format",
                "json",
                "--predicate-output",
                str(root / "predicate.json"),
                "--sbom-output",
                str(root / "sbom.json"),
            )

            self.assertEqual(0, first_result.returncode, first_result.stderr)
            self.assertEqual(0, second_result.returncode, second_result.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(0, verification.returncode, verification.stderr)
            summary = json.loads(verification.stdout)
            predicate = json.loads(
                (root / "predicate.json").read_text(encoding="utf-8")
            )
            extracted_sbom = json.loads(
                (root / "sbom.json").read_text(encoding="utf-8")
            )

        self.assertTrue(summary["valid"])
        self.assertEqual("pass", summary["gate"])
        self.assertEqual("safe_extension", summary["component"]["name"])
        self.assertEqual(
            "https://github.com/borborich/pgextassure/"
            "attestation/evidence/v1",
            predicate["predicate_type"],
        )
        self.assertEqual("SPDX-2.3", extracted_sbom["spdxVersion"])

    def test_bundle_contains_inventory_and_not_source_payloads(self) -> None:
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
            with zipfile.ZipFile(bundle) as archive:
                names = archive.namelist()
                report = json.loads(archive.read("report.json"))
                sbom = json.loads(archive.read("sbom.spdx.json"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            ["bundle.json", "report.json", "sbom.spdx.json"],
            names,
        )
        self.assertFalse(
            any(name.endswith((".sql", ".control", ".c", ".rs")) for name in names)
        )
        self.assertEqual("SPDX-2.3", sbom["spdxVersion"])
        self.assertEqual(
            len(report["manifest"]["files"]),
            len(sbom["files"]),
        )
        self.assertIn(
            "not a complete dependency-resolution claim",
            sbom["creationInfo"]["comment"],
        )

    def test_exact_policy_is_included_and_blocked_bundle_still_verifies(
        self,
    ) -> None:
        policy = FIXTURES_ROOT / "policy.json"
        with TemporaryDirectory() as directory:
            bundle = Path(directory) / "blocked.zip"
            result = run_cli(
                "evidence",
                "create",
                str(VULNERABLE_ROOT),
                "--policy",
                str(policy),
                "--created-on",
                "2026-07-29",
                "--output",
                str(bundle),
            )
            verification = verify_evidence_bundle(bundle)
            with zipfile.ZipFile(bundle) as archive:
                packaged_policy = archive.read("inputs/policy.json")

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual(policy.read_bytes(), packaged_policy)
        self.assertEqual("blocked", verification.summary["gate"])
        self.assertEqual(
            "sha256:"
            "09f99697abf9722e9f9968cbbc9f831e0e7fa3307167eee83f5351d4c80a84c6",
            verification.summary["policy_digest"],
        )

    def test_threshold_gate_is_recomputed_and_tampering_is_rejected(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "blocked.zip"
            tampered = root / "tampered-gate.zip"
            result = run_cli(
                "evidence",
                "create",
                str(VULNERABLE_ROOT),
                "--fail-on",
                "high",
                "--created-on",
                "2026-07-29",
                "--output",
                str(bundle),
            )
            with zipfile.ZipFile(bundle) as archive:
                predicate = json.loads(archive.read("bundle.json"))
            predicate["result"]["gate"] = "pass"
            _rewrite_zip(
                bundle,
                tampered,
                replace={
                    "bundle.json": (
                        json.dumps(
                            predicate,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode("utf-8")
                        + b"\n"
                    )
                },
            )
            verification = run_cli("evidence", "verify", str(tampered))

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("high", predicate["result"]["fail_on"])
        self.assertEqual(3, verification.returncode)
        self.assertIn(
            "gate result does not match the report",
            verification.stderr,
        )

    def test_exact_generation_plan_is_included(self) -> None:
        generated = FIXTURES_ROOT / "generated"
        generation_plan = generated / "generation-plan.json"
        with TemporaryDirectory() as directory:
            bundle = Path(directory) / "generated.zip"
            result = run_cli(
                "evidence",
                "create",
                str(generated),
                "--generation-plan",
                str(generation_plan),
                "--created-on",
                "2026-07-29",
                "--output",
                str(bundle),
            )
            verification = verify_evidence_bundle(bundle)
            with zipfile.ZipFile(bundle) as archive:
                packaged_plan = archive.read("inputs/generation-plan.json")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(generation_plan.read_bytes(), packaged_plan)
        self.assertEqual("pass", verification.summary["gate"])

    def test_payload_tampering_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "evidence.zip"
            tampered = root / "tampered.zip"
            result = run_cli(
                "evidence",
                "create",
                str(SAFE_ROOT),
                "--created-on",
                "2026-07-29",
                "--output",
                str(bundle),
            )
            _rewrite_zip(
                bundle,
                tampered,
                replace={"report.json": b"{}\n"},
            )

            verification = run_cli("evidence", "verify", str(tampered))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(3, verification.returncode)
        self.assertIn("does not match", verification.stderr)
        self.assertEqual("", verification.stdout)

    def test_unindexed_traversal_and_duplicate_entries_are_rejected(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "evidence.zip"
            result = run_cli(
                "evidence",
                "create",
                str(SAFE_ROOT),
                "--created-on",
                "2026-07-29",
                "--output",
                str(bundle),
            )
            traversal = root / "traversal.zip"
            duplicate = root / "duplicate.zip"
            _rewrite_zip(
                bundle,
                traversal,
                additions=[("../outside.json", b"{}\n")],
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                _rewrite_zip(
                    bundle,
                    duplicate,
                    additions=[("report.json", b"{}\n")],
                )

            traversal_result = run_cli(
                "evidence",
                "verify",
                str(traversal),
            )
            duplicate_result = run_cli(
                "evidence",
                "verify",
                str(duplicate),
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(3, traversal_result.returncode)
        self.assertIn("unsafe evidence bundle entry", traversal_result.stderr)
        self.assertEqual(3, duplicate_result.returncode)
        self.assertIn("duplicate entries", duplicate_result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires filesystem symlinks")
    def test_bundle_and_material_symlinks_are_rejected(self) -> None:
        policy = FIXTURES_ROOT / "policy.json"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "evidence.zip"
            result = run_cli(
                "evidence",
                "create",
                str(SAFE_ROOT),
                "--created-on",
                "2026-07-29",
                "--output",
                str(bundle),
            )
            linked_bundle = root / "linked.zip"
            linked_bundle.symlink_to(bundle)
            linked_policy = root / "policy.json"
            linked_policy.symlink_to(policy)

            verification = run_cli(
                "evidence",
                "verify",
                str(linked_bundle),
            )
            with self.assertRaisesRegex(EvidenceError, "must not be a symlink"):
                read_evidence_material(
                    linked_policy,
                    expected_digest=(
                        "sha256:"
                        "4ccd88117741a76a74a2ccada6244637b824315166919e40"
                        "aff61b4573bce349"
                    ),
                )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(3, verification.returncode)
        self.assertIn("must not be a symlink", verification.stderr)


if __name__ == "__main__":
    unittest.main()
