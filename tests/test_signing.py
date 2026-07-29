"""Corporate Evidence Bundle signature profile and CLI contracts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from tests.support import SAFE_ROOT, run_cli


class CorporateSignatureTests(unittest.TestCase):
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
            "--created-on",
            "2026-07-29",
            "--component-name",
            "corporate-signature-test",
            "--output",
            str(cls.bundle),
        )
        if created.returncode != 0:
            raise RuntimeError(created.stderr)
        cls.private_key = cls.root / "private.pem"
        cls.other_private_key = cls.root / "other-private.pem"
        cls.weak_private_key = cls.root / "weak-private.pem"
        cls._generate_key(cls.private_key, 3072)
        cls._generate_key(cls.other_private_key, 3072)
        cls._generate_key(cls.weak_private_key, 2048)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _generate_key(cls, path: Path, bits: int) -> None:
        result = subprocess.run(
            [
                cls.openssl,
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                f"rsa_keygen_bits:{bits}",
                "-out",
                str(path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))

    def _signed_paths(self, root: Path) -> tuple[Path, Path, Path]:
        return (
            root / "statement.json",
            root / "signature.bin",
            root / "public.pem",
        )

    def _sign(
        self,
        root: Path,
        *,
        bundle: Path | None = None,
        key: Path | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], tuple[Path, Path, Path]]:
        statement, signature, public_key = self._signed_paths(root)
        result = run_cli(
            "evidence",
            "sign",
            str(bundle or self.bundle),
            "--private-key",
            str(key or self.private_key),
            "--signer-id",
            "acme-security/release-key-01",
            "--created-on",
            "2026-07-29",
            "--openssl",
            self.openssl,
            "--statement-output",
            str(statement),
            "--signature-output",
            str(signature),
            "--public-key-output",
            str(public_key),
        )
        return result, (statement, signature, public_key)

    def test_cli_round_trip_binds_verified_bundle_and_key(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            signing, (statement, signature, public_key) = self._sign(root)
            verification = run_cli(
                "evidence",
                "verify-signature",
                str(self.bundle),
                "--statement",
                str(statement),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--openssl",
                self.openssl,
                "--format",
                "json",
            )
            document = json.loads(statement.read_text(encoding="utf-8"))
            summary = json.loads(verification.stdout)
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas"
                    / "evidence-signature-1.0.schema.json"
                ).read_text(encoding="utf-8")
            )

        self.assertEqual(0, signing.returncode, signing.stderr)
        self.assertEqual(0, verification.returncode, verification.stderr)
        self.assertTrue(summary["valid"])
        self.assertEqual("pass", summary["gate"])
        self.assertEqual("rsa-pss-sha256", summary["profile"])
        self.assertEqual(
            "pgextassure.corporate-evidence-signature",
            document["statement_type"],
        )
        self.assertEqual(
            summary["public_key_sha256"],
            document["signature"]["public_key"]["sha256"],
        )
        self.assertEqual(
            summary["subject_digest"],
            document["subject"]["digest"],
        )
        self.assertTrue(set(schema["required"]).issubset(document))

    def test_canonical_statement_tampering_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            signing, (statement, signature, public_key) = self._sign(root)
            document = json.loads(statement.read_text(encoding="utf-8"))
            document["signer"]["id"] = "attacker/replacement-key"
            statement.write_text(
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
            verification = run_cli(
                "evidence",
                "verify-signature",
                str(self.bundle),
                "--statement",
                str(statement),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--openssl",
                self.openssl,
            )

        self.assertEqual(0, signing.returncode, signing.stderr)
        self.assertEqual(3, verification.returncode)
        self.assertIn("OpenSSL rejected the operation", verification.stderr)

    def test_wrong_public_key_is_rejected_before_signature_check(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            signing, (statement, signature, public_key) = self._sign(root)
            replacement = subprocess.run(
                [
                    self.openssl,
                    "pkey",
                    "-in",
                    str(self.other_private_key),
                    "-pubout",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(0, replacement.returncode)
            public_key.write_bytes(replacement.stdout)
            verification = run_cli(
                "evidence",
                "verify-signature",
                str(self.bundle),
                "--statement",
                str(statement),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--openssl",
                self.openssl,
            )

        self.assertEqual(0, signing.returncode, signing.stderr)
        self.assertEqual(3, verification.returncode)
        self.assertIn(
            "public key does not match the signature statement",
            verification.stderr,
        )

    def test_expected_fingerprint_rejects_fully_resigned_replacement(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            original_root = root / "original"
            replacement_root = root / "replacement"
            original_root.mkdir()
            replacement_root.mkdir()
            original_signing, original_paths = self._sign(original_root)
            replacement_signing, replacement_paths = self._sign(
                replacement_root,
                key=self.other_private_key,
            )
            original_statement = json.loads(
                original_paths[0].read_text(encoding="utf-8")
            )
            expected = original_statement["signature"]["public_key"]["sha256"]
            statement, signature, public_key = replacement_paths
            verification = run_cli(
                "evidence",
                "verify-signature",
                str(self.bundle),
                "--statement",
                str(statement),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--expected-key-sha256",
                expected,
                "--openssl",
                self.openssl,
            )

        self.assertEqual(0, original_signing.returncode, original_signing.stderr)
        self.assertEqual(
            0,
            replacement_signing.returncode,
            replacement_signing.stderr,
        )
        self.assertEqual(3, verification.returncode)
        self.assertIn("trusted expected fingerprint", verification.stderr)

    def test_changed_bundle_is_rejected_before_signature_check(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            signing, (statement, signature, public_key) = self._sign(root)
            changed_bundle = root / "changed.zip"
            raw = bytearray(self.bundle.read_bytes())
            raw[len(raw) // 2] ^= 1
            changed_bundle.write_bytes(raw)
            verification = run_cli(
                "evidence",
                "verify-signature",
                str(changed_bundle),
                "--statement",
                str(statement),
                "--signature",
                str(signature),
                "--public-key",
                str(public_key),
                "--openssl",
                self.openssl,
            )

        self.assertEqual(0, signing.returncode, signing.stderr)
        self.assertEqual(3, verification.returncode)
        self.assertIn("Evidence Bundle verification failed", verification.stderr)

    def test_rsa_key_below_profile_minimum_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            signing, _ = self._sign(root, key=self.weak_private_key)

        self.assertEqual(2, signing.returncode)
        self.assertIn("must be at least 3072 bits", signing.stderr)

    def test_symlinked_private_key_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            linked_key = root / "linked-private.pem"
            try:
                linked_key.symlink_to(self.private_key)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            signing, _ = self._sign(root, key=linked_key)

        self.assertEqual(2, signing.returncode)
        self.assertIn("regular non-symlink file", signing.stderr)

    def test_signature_outputs_must_be_distinct(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / "shared"
            result = run_cli(
                "evidence",
                "sign",
                str(self.bundle),
                "--private-key",
                str(self.private_key),
                "--signer-id",
                "acme-security/release-key-01",
                "--statement-output",
                str(shared),
                "--signature-output",
                str(shared),
                "--public-key-output",
                str(root / "public.pem"),
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("output paths must be distinct", result.stderr)

    def test_signature_outputs_must_not_overwrite_private_key(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_cli(
                "evidence",
                "sign",
                str(self.bundle),
                "--private-key",
                str(self.private_key),
                "--signer-id",
                "acme-security/release-key-01",
                "--statement-output",
                str(self.private_key),
                "--signature-output",
                str(root / "signature.bin"),
                "--public-key-output",
                str(root / "public.pem"),
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("must not overwrite signing inputs", result.stderr)
        self.assertIn(b"PRIVATE KEY", self.private_key.read_bytes())

    def test_invalid_signature_date_is_usage_error(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            statement, signature, public_key = self._signed_paths(root)
            result = run_cli(
                "evidence",
                "sign",
                str(self.bundle),
                "--private-key",
                str(self.private_key),
                "--signer-id",
                "acme-security/release-key-01",
                "--created-on",
                "not-a-date",
                "--statement-output",
                str(statement),
                "--signature-output",
                str(signature),
                "--public-key-output",
                str(public_key),
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("signature created_on", result.stderr)

    def test_passphrase_environment_supports_encrypted_private_key(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            encrypted_key = root / "encrypted-private.pem"
            encrypted = subprocess.run(
                [
                    self.openssl,
                    "pkey",
                    "-in",
                    str(self.private_key),
                    "-aes-256-cbc",
                    "-passout",
                    "pass:correct horse battery staple",
                    "-out",
                    str(encrypted_key),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(0, encrypted.returncode, encrypted.stderr)
            statement, signature, public_key = self._signed_paths(root)
            old_value = os.environ.get("PGEXTASSURE_TEST_PASSPHRASE")
            os.environ["PGEXTASSURE_TEST_PASSPHRASE"] = (
                "correct horse battery staple"
            )
            try:
                signing = run_cli(
                    "evidence",
                    "sign",
                    str(self.bundle),
                    "--private-key",
                    str(encrypted_key),
                    "--signer-id",
                    "acme-security/release-key-01",
                    "--passphrase-env",
                    "PGEXTASSURE_TEST_PASSPHRASE",
                    "--openssl",
                    self.openssl,
                    "--statement-output",
                    str(statement),
                    "--signature-output",
                    str(signature),
                    "--public-key-output",
                    str(public_key),
                )
            finally:
                if old_value is None:
                    os.environ.pop("PGEXTASSURE_TEST_PASSPHRASE", None)
                else:
                    os.environ["PGEXTASSURE_TEST_PASSPHRASE"] = old_value

        self.assertEqual(0, signing.returncode, signing.stderr)
