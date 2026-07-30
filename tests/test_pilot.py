"""Enterprise pilot handoff package contracts."""

from __future__ import annotations

import hashlib
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import zipfile

from tests.support import run_cli


REQUIRED_CONTENT = {
    "README.md": b"# Reference pilot\n",
    "acceptance-criteria.md": b"# Acceptance criteria\n",
    "enterprise-trust-policy.json": b"{}\n",
    "evidence-verify.json": b'{"valid":true}\n',
    "pgextassure-admission-receipt.json": b"{}\n",
    "pgextassure-evidence.zip": b"evidence-placeholder",
    "pgextassure-public-key.pem": (
        b"-----BEGIN PUBLIC KEY-----\nreference\n"
        b"-----END PUBLIC KEY-----\n"
    ),
    "pgextassure-signature.bin": b"signature-placeholder",
    "pgextassure-signature.json": b"{}\n",
    "receipt-verify.json": b'{"active":true,"valid":true}\n',
    "release-provenance.json": b'[{"verified":true}]\n',
    "security-questionnaire.md": b"# Security questionnaire\n",
    "signature-verify.json": b'{"valid":true}\n',
    "verification.md": b"# Independent verification\n",
}
WHEEL_NAME = "pgextassure-0.1.0a13-py3-none-any.whl"
SDIST_NAME = "pgextassure-0.1.0a13.tar.gz"


class EnterprisePilotPackageTests(unittest.TestCase):
    def _staging(self, root: Path) -> Path:
        staging = root / "staging"
        staging.mkdir()
        for name, content in REQUIRED_CONTENT.items():
            (staging / name).write_bytes(content)
        wheel = b"wheel-placeholder"
        sdist = b"sdist-placeholder"
        (staging / WHEEL_NAME).write_bytes(wheel)
        (staging / SDIST_NAME).write_bytes(sdist)
        checksums = (
            f"{hashlib.sha256(wheel).hexdigest()}  ./{WHEEL_NAME}\n"
            f"{hashlib.sha256(sdist).hexdigest()}  ./{SDIST_NAME}\n"
        )
        (staging / "release-SHA256SUMS").write_text(
            checksums,
            encoding="ascii",
        )
        return staging

    def test_cli_package_is_deterministic_and_verifies_offline(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            staging = self._staging(root)
            first = root / "first.zip"
            second = root / "second.zip"
            first_result = run_cli(
                "pilot",
                "package",
                str(staging),
                "--output",
                str(first),
                "--format",
                "json",
            )
            second_result = run_cli(
                "pilot",
                "package",
                str(staging),
                "--output",
                str(second),
                "--format",
                "json",
            )
            verification = run_cli(
                "pilot",
                "verify-package",
                str(first),
                "--format",
                "json",
            )
            with zipfile.ZipFile(first, mode="r") as archive:
                manifest_raw = archive.read("pilot-package.json")
                names = archive.namelist()
            first_bytes = first.read_bytes()
            second_bytes = second.read_bytes()
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas"
                    / "pilot-package-1.0.schema.json"
                ).read_text(encoding="utf-8")
            )

        self.assertEqual(0, first_result.returncode, first_result.stderr)
        self.assertEqual(0, second_result.returncode, second_result.stderr)
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(0, verification.returncode, verification.stderr)
        summary = json.loads(verification.stdout)
        manifest = json.loads(manifest_raw)
        self.assertTrue(summary["valid"])
        self.assertEqual(17, summary["files"])
        self.assertEqual(
            "pgextassure.enterprise-pilot-package",
            manifest["package_type"],
        )
        self.assertTrue(set(schema["required"]).issubset(manifest))
        self.assertEqual(sorted(names), names)

    def test_private_key_and_unexpected_file_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            staging = self._staging(root)
            output = root / "pilot.zip"
            (staging / "README.md").write_bytes(
                b"-----BEGIN PRIVATE KEY-----\nsecret\n"
            )
            private_key = run_cli(
                "pilot",
                "package",
                str(staging),
                "--output",
                str(output),
            )
            (staging / "README.md").write_bytes(REQUIRED_CONTENT["README.md"])
            (staging / "source.sql").write_text("SELECT 1;\n", encoding="utf-8")
            unexpected = run_cli(
                "pilot",
                "package",
                str(staging),
                "--output",
                str(output),
            )

        self.assertEqual(2, private_key.returncode)
        self.assertIn("private-key material", private_key.stderr)
        self.assertEqual(2, unexpected.returncode)
        self.assertIn("unexpected file", unexpected.stderr)
        self.assertFalse(output.exists())

    def test_symlink_and_output_inside_staging_are_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            staging = self._staging(root)
            target = staging / "README.md"
            alias = staging / "verification.md"
            alias.unlink()
            try:
                alias.symlink_to(target.name)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            symlinked = run_cli(
                "pilot",
                "package",
                str(staging),
                "--output",
                str(root / "pilot.zip"),
            )
            alias.unlink()
            alias.write_bytes(REQUIRED_CONTENT["verification.md"])
            inside = run_cli(
                "pilot",
                "package",
                str(staging),
                "--output",
                str(staging / "pilot.zip"),
            )

        self.assertEqual(2, symlinked.returncode)
        self.assertIn("regular non-symlink file", symlinked.stderr)
        self.assertEqual(2, inside.returncode)
        self.assertIn("outside its staging directory", inside.stderr)

    def test_payload_tampering_is_rejected_without_extraction(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            staging = self._staging(root)
            package = root / "pilot.zip"
            creation = run_cli(
                "pilot",
                "package",
                str(staging),
                "--output",
                str(package),
            )
            self.assertEqual(0, creation.returncode, creation.stderr)
            with zipfile.ZipFile(package, mode="r") as source:
                files = {
                    information.filename: source.read(information)
                    for information in source.infolist()
                }
            files["README.md"] += b"tampered\n"
            output = BytesIO()
            with zipfile.ZipFile(output, mode="w") as archive:
                for name in sorted(files):
                    archive.writestr(name, files[name])
            package.write_bytes(output.getvalue())
            verification = run_cli(
                "pilot",
                "verify-package",
                str(package),
            )

        self.assertEqual(3, verification.returncode)
        self.assertIn("does not match its manifest", verification.stderr)


if __name__ == "__main__":
    unittest.main()
