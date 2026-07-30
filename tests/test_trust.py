"""Enterprise Trust Policy and Admission Receipt contracts."""

from __future__ import annotations

from datetime import date
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from pgextassure.trust import load_trust_policy
from tests.support import FIXTURES_ROOT, SAFE_ROOT, VULNERABLE_ROOT, run_cli


class EnterpriseTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        openssl = shutil.which("openssl")
        if openssl is None:
            raise unittest.SkipTest("OpenSSL is not installed")
        cls.openssl = openssl
        cls.temporary = TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.private_key = cls.root / "private.pem"
        cls.other_private_key = cls.root / "other-private.pem"
        cls._generate_key(cls.private_key)
        cls._generate_key(cls.other_private_key)
        cls.approved_bundle = cls.root / "approved.zip"
        cls.blocked_bundle = cls.root / "blocked.zip"
        policy = FIXTURES_ROOT / "policy.json"
        approved = run_cli(
            "evidence",
            "create",
            str(SAFE_ROOT),
            "--policy",
            str(policy),
            "--created-on",
            "2026-07-29",
            "--component-name",
            "trust-approved",
            "--output",
            str(cls.approved_bundle),
        )
        blocked = run_cli(
            "evidence",
            "create",
            str(VULNERABLE_ROOT),
            "--policy",
            str(policy),
            "--created-on",
            "2026-07-29",
            "--component-name",
            "trust-blocked",
            "--output",
            str(cls.blocked_bundle),
        )
        if approved.returncode != 0:
            raise RuntimeError(approved.stderr)
        if blocked.returncode != 1:
            raise RuntimeError(blocked.stderr)
        (
            cls.approved_statement,
            cls.approved_signature,
            cls.public_key,
        ) = cls._sign(cls.approved_bundle, cls.private_key, "trusted/key-01")
        (
            cls.blocked_statement,
            cls.blocked_signature,
            cls.blocked_public_key,
        ) = cls._sign(cls.blocked_bundle, cls.private_key, "trusted/key-01")
        cls.statement_document = json.loads(
            cls.approved_statement.read_text(encoding="utf-8")
        )
        cls.key_digest = cls.statement_document["signature"]["public_key"][
            "sha256"
        ]
        cls.evidence_policy_digest = cls.statement_document["evidence"][
            "policy_digest"
        ]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _generate_key(cls, path: Path) -> None:
        result = subprocess.run(
            [
                cls.openssl,
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:3072",
                "-out",
                str(path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))

    @classmethod
    def _sign(
        cls,
        bundle: Path,
        key: Path,
        signer_id: str,
    ) -> tuple[Path, Path, Path]:
        stem = bundle.stem + "-" + key.stem
        statement = cls.root / f"{stem}-statement.json"
        signature = cls.root / f"{stem}-signature.bin"
        public_key = cls.root / f"{stem}-public.pem"
        result = run_cli(
            "evidence",
            "sign",
            str(bundle),
            "--private-key",
            str(key),
            "--signer-id",
            signer_id,
            "--created-on",
            "2026-07-29",
            "--openssl",
            cls.openssl,
            "--statement-output",
            str(statement),
            "--signature-output",
            str(signature),
            "--public-key-output",
            str(public_key),
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        return statement, signature, public_key

    def _policy_document(
        self,
        *,
        key_digest: str | None = None,
        signer_id: str = "trusted/key-01",
        revoked_on: str | None = None,
        allowed_policy_digest: str | None = None,
        maximum_age: int = 30,
        allowed_gates: list[str] | None = None,
    ) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "policy_type": "pgextassure.enterprise-trust-policy",
            "policy_id": "acme/postgresql-production",
            "effective_from": "2026-07-01",
            "expires_on": "2026-12-31",
            "requirements": {
                "allowed_gates": allowed_gates or ["pass"],
                "allowed_tool_versions": ["0.1.0-alpha.13"],
                "allowed_ruleset_versions": ["2026-07-29.6"],
                "allowed_evidence_schema_versions": ["1.0"],
                "allowed_policy_digests": [
                    allowed_policy_digest or self.evidence_policy_digest
                ],
                "maximum_evidence_age_days": maximum_age,
                "maximum_signature_age_days": maximum_age,
                "receipt_valid_days": 7,
            },
            "signers": [
                {
                    "id": signer_id,
                    "public_key_sha256": key_digest or self.key_digest,
                    "valid_from": "2026-07-01",
                    "valid_until": "2026-12-31",
                    "revoked_on": revoked_on,
                }
            ],
        }

    def _write_policy(
        self,
        root: Path,
        document: dict[str, object] | None = None,
    ) -> Path:
        path = root / "trust-policy.json"
        path.write_text(
            json.dumps(
                document or self._policy_document(),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def _evaluate(
        self,
        root: Path,
        policy: Path,
        *,
        bundle: Path | None = None,
        statement: Path | None = None,
        signature: Path | None = None,
        public_key: Path | None = None,
        evaluated_on: str = "2026-07-29",
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        receipt = root / "receipt.json"
        result = run_cli(
            "trust",
            "evaluate",
            str(bundle or self.approved_bundle),
            "--statement",
            str(statement or self.approved_statement),
            "--signature",
            str(signature or self.approved_signature),
            "--public-key",
            str(public_key or self.public_key),
            "--trust-policy",
            str(policy),
            "--evaluated-on",
            evaluated_on,
            "--request-id",
            "CHG-2026-0042",
            "--target",
            "postgresql-prod-eu/extension-slot-01",
            "--openssl",
            self.openssl,
            "--output",
            str(receipt),
            "--format",
            "json",
        )
        return result, receipt

    def _verify(
        self,
        receipt: Path,
        policy: Path,
        *,
        bundle: Path | None = None,
        statement: Path | None = None,
        signature: Path | None = None,
        public_key: Path | None = None,
        verified_on: str = "2026-07-29",
        expected_policy_digest: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            "trust",
            "verify-receipt",
            str(receipt),
            "--bundle",
            str(bundle or self.approved_bundle),
            "--statement",
            str(statement or self.approved_statement),
            "--signature",
            str(signature or self.approved_signature),
            "--public-key",
            str(public_key or self.public_key),
            "--trust-policy",
            str(policy),
            "--expected-request-id",
            "CHG-2026-0042",
            "--expected-target",
            "postgresql-prod-eu/extension-slot-01",
            "--expected-evaluated-on",
            "2026-07-29",
            "--verified-on",
            verified_on,
            "--openssl",
            self.openssl,
            "--format",
            "json",
        ]
        if expected_policy_digest is not None:
            arguments.extend(
                ["--expected-trust-policy-sha256", expected_policy_digest]
            )
        return run_cli(*arguments)

    def test_admit_receipt_round_trips_with_trusted_policy_digest(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = self._write_policy(root)
            evaluation, receipt = self._evaluate(root, policy)
            policy_digest = "sha256:" + hashlib.sha256(
                policy.read_bytes()
            ).hexdigest()
            verification = self._verify(
                receipt,
                policy,
                expected_policy_digest=policy_digest,
            )
            document = json.loads(receipt.read_text(encoding="utf-8"))
            summary = json.loads(verification.stdout)
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas"
                    / "admission-receipt-1.0.schema.json"
                ).read_text(encoding="utf-8")
            )
            policy_schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas"
                    / "enterprise-trust-policy-1.0.schema.json"
                ).read_text(encoding="utf-8")
            )
            policy_document = json.loads(policy.read_text(encoding="utf-8"))

        self.assertEqual(0, evaluation.returncode, evaluation.stderr)
        self.assertEqual(0, verification.returncode, verification.stderr)
        self.assertEqual("admit", document["decision"]["result"])
        self.assertEqual([], document["decision"]["reasons"])
        self.assertEqual("2026-08-05", document["validity"]["valid_until"])
        self.assertTrue(summary["active"])
        self.assertTrue(set(schema["required"]).issubset(document))
        self.assertTrue(
            set(policy_schema["required"]).issubset(policy_document)
        )

    def test_enterprise_example_trust_policy_is_current_and_closed(self) -> None:
        path = (
            Path(__file__).resolve().parents[1]
            / "examples"
            / "enterprise"
            / "trust-policy.json"
        )
        policy = load_trust_policy(path)

        self.assertEqual("example/postgresql-production", policy.policy_id)
        self.assertEqual(
            ("0.1.0-alpha.13",),
            policy.requirements.allowed_tool_versions,
        )
        self.assertEqual(
            ("2026-07-29.6",),
            policy.requirements.allowed_ruleset_versions,
        )
        self.assertEqual(
            "sha256:" + ("0" * 64),
            policy.signers[0].public_key_sha256,
        )

    def test_blocked_gate_produces_verifiable_deny_receipt(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = self._write_policy(root)
            evaluation, receipt = self._evaluate(
                root,
                policy,
                bundle=self.blocked_bundle,
                statement=self.blocked_statement,
                signature=self.blocked_signature,
                public_key=self.blocked_public_key,
            )
            verification = self._verify(
                receipt,
                policy,
                bundle=self.blocked_bundle,
                statement=self.blocked_statement,
                signature=self.blocked_signature,
                public_key=self.blocked_public_key,
            )
            document = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(1, evaluation.returncode, evaluation.stderr)
        self.assertEqual(1, verification.returncode, verification.stderr)
        self.assertEqual("deny", document["decision"]["result"])
        self.assertIn("gate-not-allowed", document["decision"]["reasons"])
        self.assertFalse(json.loads(verification.stdout)["active"])

    def test_revoked_key_is_denied(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = self._write_policy(
                root,
                self._policy_document(revoked_on="2026-07-29"),
            )
            evaluation, receipt = self._evaluate(root, policy)
            document = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(1, evaluation.returncode, evaluation.stderr)
        self.assertIn("signer-revoked", document["decision"]["reasons"])

    def test_stale_evidence_and_signature_are_denied(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = self._write_policy(
                root,
                self._policy_document(maximum_age=7),
            )
            evaluation, receipt = self._evaluate(
                root,
                policy,
                evaluated_on="2026-08-06",
            )
            document = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(1, evaluation.returncode, evaluation.stderr)
        self.assertIn("evidence-too-old", document["decision"]["reasons"])
        self.assertIn("signature-too-old", document["decision"]["reasons"])

    def test_wrong_evidence_policy_is_denied(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = self._write_policy(
                root,
                self._policy_document(
                    allowed_policy_digest="sha256:" + ("0" * 64)
                ),
            )
            evaluation, receipt = self._evaluate(root, policy)
            document = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(1, evaluation.returncode, evaluation.stderr)
        self.assertIn(
            "evidence-policy-not-allowed",
            document["decision"]["reasons"],
        )

    def test_untrusted_signer_is_denied(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (
                replacement_statement,
                replacement_signature,
                replacement_public_key,
            ) = self._sign(
                self.approved_bundle,
                self.other_private_key,
                "attacker/key-01",
            )
            policy = self._write_policy(root)
            evaluation, receipt = self._evaluate(
                root,
                policy,
                statement=replacement_statement,
                signature=replacement_signature,
                public_key=replacement_public_key,
            )
            document = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(1, evaluation.returncode, evaluation.stderr)
        self.assertIn("untrusted-signer", document["decision"]["reasons"])

    def test_receipt_tampering_fails_recomputation(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = self._write_policy(root)
            evaluation, receipt = self._evaluate(root, policy)
            document = json.loads(receipt.read_text(encoding="utf-8"))
            document["request"]["target"] = "attacker/replacement-target"
            receipt.write_text(
                json.dumps(
                    document,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            verification = self._verify(receipt, policy)

        self.assertEqual(0, evaluation.returncode, evaluation.stderr)
        self.assertEqual(3, verification.returncode)
        self.assertIn("trusted request context", verification.stderr)

    def test_expired_receipt_is_valid_but_not_active(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = self._write_policy(root)
            evaluation, receipt = self._evaluate(root, policy)
            verification = self._verify(
                receipt,
                policy,
                verified_on="2026-08-06",
            )
            summary = json.loads(verification.stdout)

        self.assertEqual(0, evaluation.returncode, evaluation.stderr)
        self.assertEqual(1, verification.returncode, verification.stderr)
        self.assertTrue(summary["valid"])
        self.assertFalse(summary["active"])

    def test_wrong_trusted_policy_digest_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = self._write_policy(root)
            evaluation, receipt = self._evaluate(root, policy)
            verification = self._verify(
                receipt,
                policy,
                expected_policy_digest="sha256:" + ("0" * 64),
            )

        self.assertEqual(0, evaluation.returncode, evaluation.stderr)
        self.assertEqual(3, verification.returncode)
        self.assertIn("does not match the trusted digest", verification.stderr)

    def test_duplicate_keys_and_symlinked_policy_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "duplicate.json"
            policy.write_text(
                '{"schema_version":"1.0","schema_version":"1.0"}\n',
                encoding="utf-8",
            )
            duplicate, _receipt = self._evaluate(root, policy)
            valid_policy = self._write_policy(root)
            linked = root / "linked-policy.json"
            try:
                linked.symlink_to(valid_policy)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            symlinked, _receipt = self._evaluate(root, linked)

        self.assertEqual(2, duplicate.returncode)
        self.assertIn("duplicate JSON key", duplicate.stderr)
        self.assertEqual(2, symlinked.returncode)
        self.assertIn("regular non-symlink file", symlinked.stderr)


if __name__ == "__main__":
    unittest.main()
