"""One-shot enterprise admission integration contracts."""

from __future__ import annotations

from io import BytesIO
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
import zipfile

from pgextassure._version import RELEASE_VERSION
from pgextassure.scanner import RULESET_VERSION
from tests.support import FIXTURES_ROOT, SAFE_ROOT, run_cli


class EnterpriseAdmissionIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        openssl = shutil.which("openssl")
        if openssl is None:
            raise unittest.SkipTest("OpenSSL is not installed")
        cls.openssl = openssl
        cls.temporary = TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.bundle = cls.root / "evidence.zip"
        created = run_cli(
            "evidence",
            "create",
            str(SAFE_ROOT),
            "--policy",
            str(FIXTURES_ROOT / "policy.json"),
            "--created-on",
            "2026-07-29",
            "--component-name",
            "enterprise-integration-test",
            "--component-version",
            "1.0",
            "--output",
            str(cls.bundle),
        )
        if created.returncode != 0:
            raise RuntimeError(created.stderr)

        cls.private_key = cls.root / "private.pem"
        generated = subprocess.run(
            [
                openssl,
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:3072",
                "-out",
                str(cls.private_key),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if generated.returncode != 0:
            raise RuntimeError(
                generated.stderr.decode("utf-8", errors="replace")
            )
        cls.statement = cls.root / "statement.json"
        cls.signature = cls.root / "signature.bin"
        cls.public_key = cls.root / "public.pem"
        signed = run_cli(
            "evidence",
            "sign",
            str(cls.bundle),
            "--private-key",
            str(cls.private_key),
            "--signer-id",
            "enterprise/key-01",
            "--created-on",
            "2026-07-29",
            "--openssl",
            openssl,
            "--statement-output",
            str(cls.statement),
            "--signature-output",
            str(cls.signature),
            "--public-key-output",
            str(cls.public_key),
        )
        if signed.returncode != 0:
            raise RuntimeError(signed.stderr)
        statement = json.loads(cls.statement.read_text(encoding="utf-8"))
        cls.key_digest = statement["signature"]["public_key"]["sha256"]
        trust_document = {
            "schema_version": "1.0",
            "policy_type": "pgextassure.enterprise-trust-policy",
            "policy_id": "enterprise/postgresql-production",
            "effective_from": "2026-07-01",
            "expires_on": "2026-12-31",
            "requirements": {
                "allowed_gates": ["pass"],
                "allowed_tool_versions": [RELEASE_VERSION],
                "allowed_ruleset_versions": [RULESET_VERSION],
                "allowed_evidence_schema_versions": ["1.0"],
                "allowed_policy_digests": [
                    statement["evidence"]["policy_digest"]
                ],
                "maximum_evidence_age_days": 30,
                "maximum_signature_age_days": 30,
                "receipt_valid_days": 7,
            },
            "signers": [
                {
                    "id": "enterprise/key-01",
                    "public_key_sha256": cls.key_digest,
                    "valid_from": "2026-07-01",
                    "valid_until": "2026-12-31",
                    "revoked_on": None,
                }
            ],
        }
        cls.trust_policy = cls.root / "trust-policy.json"
        cls.trust_policy.write_text(
            json.dumps(
                trust_document,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        cls.trust_digest = "sha256:" + hashlib.sha256(
            cls.trust_policy.read_bytes()
        ).hexdigest()
        cls.receipt = cls.root / "receipt.json"
        evaluated = run_cli(
            "trust",
            "evaluate",
            str(cls.bundle),
            "--statement",
            str(cls.statement),
            "--signature",
            str(cls.signature),
            "--public-key",
            str(cls.public_key),
            "--trust-policy",
            str(cls.trust_policy),
            "--evaluated-on",
            "2026-07-29",
            "--request-id",
            "PILOT-INTEGRATION-001",
            "--target",
            "postgresql-prod/extension-slot-01",
            "--openssl",
            openssl,
            "--output",
            str(cls.receipt),
        )
        if evaluated.returncode != 0:
            raise RuntimeError(evaluated.stderr)
        cls.package = cls._create_package()
        cls.package_digest = "sha256:" + hashlib.sha256(
            cls.package.read_bytes()
        ).hexdigest()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _create_package(cls) -> Path:
        staging = cls.root / "staging"
        staging.mkdir()
        content = {
            "README.md": b"# Enterprise integration test\n",
            "acceptance-criteria.md": b"# Acceptance criteria\n",
            "evidence-verify.json": b'{"valid":true}\n',
            "receipt-verify.json": b'{"active":true,"valid":true}\n',
            "release-provenance.json": b"[]\n",
            "security-questionnaire.md": b"# Security questionnaire\n",
            "signature-verify.json": b'{"valid":true}\n',
            "verification.md": b"# Verification\n",
        }
        for name, raw in content.items():
            (staging / name).write_bytes(raw)
        copies = {
            cls.bundle: "pgextassure-evidence.zip",
            cls.statement: "pgextassure-signature.json",
            cls.signature: "pgextassure-signature.bin",
            cls.public_key: "pgextassure-public-key.pem",
            cls.trust_policy: "enterprise-trust-policy.json",
            cls.receipt: "pgextassure-admission-receipt.json",
        }
        for source, name in copies.items():
            shutil.copyfile(source, staging / name)
        wheel_name = "pgextassure-0.1.0a16-py3-none-any.whl"
        sdist_name = "pgextassure-0.1.0a16.tar.gz"
        wheel = b"wheel-integration-placeholder"
        sdist = b"sdist-integration-placeholder"
        (staging / wheel_name).write_bytes(wheel)
        (staging / sdist_name).write_bytes(sdist)
        (staging / "release-SHA256SUMS").write_text(
            f"{hashlib.sha256(wheel).hexdigest()}  ./{wheel_name}\n"
            f"{hashlib.sha256(sdist).hexdigest()}  ./{sdist_name}\n",
            encoding="ascii",
        )
        package = cls.root / "enterprise-pilot.zip"
        result = run_cli(
            "pilot",
            "package",
            str(staging),
            "--output",
            str(package),
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
        return package

    def _enforce(
        self,
        root: Path,
        *,
        package: Path | None = None,
        package_digest: str | None = None,
        request_id: str = "PILOT-INTEGRATION-001",
        verified_on: str = "2026-07-29",
    ) -> subprocess.CompletedProcess[str]:
        return run_cli(
            "pilot",
            "enforce",
            str(package or self.package),
            "--expected-package-sha256",
            package_digest or self.package_digest,
            "--expected-key-sha256",
            self.key_digest,
            "--expected-trust-policy-sha256",
            self.trust_digest,
            "--expected-request-id",
            request_id,
            "--expected-target",
            "postgresql-prod/extension-slot-01",
            "--expected-evaluated-on",
            "2026-07-29",
            "--verified-on",
            verified_on,
            "--openssl",
            self.openssl,
            "--event-output",
            str(root / "admission-event.json"),
            "--format",
            "json",
        )

    def test_allow_event_is_recomputed_and_schema_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            result = self._enforce(root)
            event_raw = (root / "admission-event.json").read_bytes()
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas"
                    / "admission-event-1.0.schema.json"
                ).read_text(encoding="utf-8")
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(event_raw.decode("utf-8"), result.stdout)
        event = json.loads(result.stdout)
        self.assertEqual("allow", event["outcome"])
        self.assertTrue(event["active"])
        self.assertEqual(self.package_digest, event["package"]["digest"])
        self.assertEqual(self.key_digest, event["signature"]["public_key_sha256"])
        self.assertEqual(set(schema["required"]), set(event))

    def test_expired_receipt_emits_deny_event_and_exit_one(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            result = self._enforce(root, verified_on="2026-08-06")
            event = json.loads(
                (root / "admission-event.json").read_text(encoding="utf-8")
            )
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("deny", event["outcome"])
        self.assertFalse(event["active"])
        self.assertEqual("admit", event["decision"]["result"])

    def test_wrong_package_digest_and_request_context_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            wrong_digest = self._enforce(
                root,
                package_digest="sha256:" + "0" * 64,
            )
            wrong_context = self._enforce(
                root,
                request_id="PILOT-INTEGRATION-REPLAY",
            )
        self.assertEqual(3, wrong_digest.returncode)
        self.assertIn("trusted expected digest", wrong_digest.stderr)
        self.assertEqual(3, wrong_context.returncode)
        self.assertIn("trusted request context", wrong_context.stderr)

    def test_payload_tamper_fails_before_embedded_reports_are_trusted(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tampered = root / "tampered.zip"
            with zipfile.ZipFile(self.package, mode="r") as source:
                files = {
                    information.filename: source.read(information)
                    for information in source.infolist()
                }
            files["receipt-verify.json"] = b'{"active":true,"valid":false}\n'
            output = BytesIO()
            with zipfile.ZipFile(output, mode="w") as archive:
                for name in sorted(files):
                    archive.writestr(name, files[name])
            tampered.write_bytes(output.getvalue())
            digest = "sha256:" + hashlib.sha256(
                tampered.read_bytes()
            ).hexdigest()
            result = self._enforce(
                root,
                package=tampered,
                package_digest=digest,
            )
        self.assertEqual(3, result.returncode)
        self.assertIn("does not match its manifest", result.stderr)


if __name__ == "__main__":
    unittest.main()
