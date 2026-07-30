"""Self-service enterprise pilot acceptance contracts."""

from __future__ import annotations

from datetime import date
import hashlib
import json
from pathlib import Path
import shutil
import ssl
import subprocess
from tempfile import TemporaryDirectory
import threading
import unittest

from pgextassure.acceptance import (
    PilotAcceptanceConfigurationError,
    run_pilot_acceptance,
)
from pgextassure.gateway import GatewayConfig, create_gateway_server
from tests.support import run_cli
from tests import test_enterprise


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PilotAcceptanceIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_type = test_enterprise.EnterpriseAdmissionIntegrationTests
        fixture_type.setUpClass()
        cls.fixture = fixture_type
        cls.tls_temporary = TemporaryDirectory()
        cls.tls_root = Path(cls.tls_temporary.name)
        cls._create_tls_material()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tls_temporary.cleanup()
        cls.fixture.tearDownClass()

    @classmethod
    def _openssl(cls, *arguments: str) -> None:
        result = subprocess.run(
            [cls.fixture.openssl, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.decode("utf-8", errors="replace")
            )

    @classmethod
    def _create_tls_material(cls) -> None:
        cls.ca_key = cls.tls_root / "ca-key.pem"
        cls.ca_certificate = cls.tls_root / "ca.pem"
        cls.server_key = cls.tls_root / "server-key.pem"
        cls.server_csr = cls.tls_root / "server.csr"
        cls.server_certificate = cls.tls_root / "server.pem"
        cls.client_key = cls.tls_root / "client-key.pem"
        cls.client_csr = cls.tls_root / "client.csr"
        cls.client_certificate = cls.tls_root / "client.pem"
        cls._openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=PgExtAssure Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(cls.ca_key),
            "-out",
            str(cls.ca_certificate),
        )
        cls._openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-sha256",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(cls.server_key),
            "-out",
            str(cls.server_csr),
        )
        server_extensions = cls.tls_root / "server.ext"
        server_extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:localhost\n",
            encoding="ascii",
        )
        cls._openssl(
            "x509",
            "-req",
            "-sha256",
            "-days",
            "2",
            "-in",
            str(cls.server_csr),
            "-CA",
            str(cls.ca_certificate),
            "-CAkey",
            str(cls.ca_key),
            "-CAcreateserial",
            "-extfile",
            str(server_extensions),
            "-out",
            str(cls.server_certificate),
        )
        cls._openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-sha256",
            "-subj",
            "/CN=pgextassure-acceptance-client",
            "-keyout",
            str(cls.client_key),
            "-out",
            str(cls.client_csr),
        )
        client_extensions = cls.tls_root / "client.ext"
        client_extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=clientAuth\n",
            encoding="ascii",
        )
        cls._openssl(
            "x509",
            "-req",
            "-sha256",
            "-days",
            "2",
            "-in",
            str(cls.client_csr),
            "-CA",
            str(cls.ca_certificate),
            "-CAkey",
            str(cls.ca_key),
            "-CAcreateserial",
            "-extfile",
            str(client_extensions),
            "-out",
            str(cls.client_certificate),
        )
        cls.client_key.chmod(0o600)

    def setUp(self) -> None:
        self.server_temporary = TemporaryDirectory()
        server_root = Path(self.server_temporary.name).resolve()
        self.server = create_gateway_server(
            GatewayConfig(
                host="127.0.0.1",
                port=0,
                ledger_path=server_root / "admissions.sqlite3",
                openssl_path=self.fixture.openssl,
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(
            certfile=str(self.server_certificate),
            keyfile=str(self.server_key),
        )
        context.load_verify_locations(cafile=str(self.ca_certificate))
        context.verify_mode = ssl.CERT_REQUIRED
        self.server.socket = context.wrap_socket(
            self.server.socket,
            server_side=True,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        self.gateway_url = (
            f"https://localhost:{self.server.server_address[1]}"
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.server_temporary.cleanup()

    def _accept(
        self,
        *,
        idempotency_key: str = "pilot-acceptance-001",
        client_key: Path | None = None,
    ):
        return run_pilot_acceptance(
            self.fixture.package,
            gateway_url=self.gateway_url,
            ca_certificate_path=self.ca_certificate,
            client_certificate_path=self.client_certificate,
            client_key_path=client_key or self.client_key,
            expected_package_sha256=self.fixture.package_digest,
            expected_public_key_sha256=self.fixture.key_digest,
            expected_trust_policy_sha256=self.fixture.trust_digest,
            expected_request_id="PILOT-INTEGRATION-001",
            expected_target="postgresql-prod/extension-slot-01",
            expected_evaluated_on=date(2026, 7, 29),
            verified_on=date(2026, 7, 29),
            idempotency_key=idempotency_key,
            openssl_path=self.fixture.openssl,
        )

    def test_accepts_tls13_mtls_admission_and_exact_replay(self) -> None:
        acceptance = self._accept()
        schema = json.loads(
            (
                PROJECT_ROOT
                / "schemas"
                / "pilot-acceptance-report-1.0.schema.json"
            ).read_text(encoding="utf-8")
        )

        self.assertTrue(acceptance.accepted)
        self.assertTrue(acceptance.document["accepted"])
        self.assertEqual(set(schema["required"]), set(acceptance.document))
        self.assertEqual(
            ["pass"] * 6,
            [check["status"] for check in acceptance.document["checks"]],
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(
                self.ca_certificate.read_bytes()
            ).hexdigest(),
            acceptance.document["transport"]["ca_certificate_sha256"],
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(
                self.client_certificate.read_bytes()
            ).hexdigest(),
            acceptance.document["transport"]["client_certificate_sha256"],
        )
        server_der = ssl.PEM_cert_to_DER_cert(
            self.server_certificate.read_text(encoding="ascii")
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(server_der).hexdigest(),
            acceptance.document["transport"]["server_certificate_sha256"],
        )
        self.assertEqual(
            acceptance.report,
            (
                json.dumps(
                    acceptance.document,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8"),
        )
        self.assertNotIn(
            str(self.client_key).encode("utf-8"),
            acceptance.report,
        )
        self.assertNotIn(b"pilot-acceptance-001", acceptance.report)

    def test_cli_writes_canonical_report_and_returns_zero(self) -> None:
        with TemporaryDirectory() as directory:
            report_path = Path(directory) / "acceptance.json"
            result = run_cli(
                "pilot",
                "accept",
                str(self.fixture.package),
                "--gateway-url",
                self.gateway_url,
                "--ca-certificate",
                str(self.ca_certificate),
                "--client-certificate",
                str(self.client_certificate),
                "--client-key",
                str(self.client_key),
                "--expected-package-sha256",
                self.fixture.package_digest,
                "--expected-key-sha256",
                self.fixture.key_digest,
                "--expected-trust-policy-sha256",
                self.fixture.trust_digest,
                "--expected-request-id",
                "PILOT-INTEGRATION-001",
                "--expected-target",
                "postgresql-prod/extension-slot-01",
                "--expected-evaluated-on",
                "2026-07-29",
                "--verified-on",
                "2026-07-29",
                "--idempotency-key",
                "pilot-acceptance-cli-001",
                "--openssl",
                self.fixture.openssl,
                "--output",
                str(report_path),
                "--format",
                "json",
            )
            report_raw = report_path.read_bytes()

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(report_raw.decode("utf-8"), result.stdout)
        self.assertTrue(json.loads(result.stdout)["accepted"])

    def test_existing_idempotency_key_fails_the_first_admission_check(self) -> None:
        first = self._accept(idempotency_key="pilot-acceptance-reused")
        second = self._accept(idempotency_key="pilot-acceptance-reused")

        self.assertTrue(first.accepted)
        self.assertFalse(second.accepted)
        self.assertEqual(
            {
                "id": "first-admission",
                "status": "fail",
                "code": "first-admission-failed",
            },
            second.document["checks"][4],
        )
        self.assertEqual("not-run", second.document["checks"][5]["status"])

    def test_offline_integrity_failure_still_returns_closed_report(self) -> None:
        acceptance = run_pilot_acceptance(
            self.fixture.package,
            gateway_url=self.gateway_url,
            ca_certificate_path=self.ca_certificate,
            client_certificate_path=self.client_certificate,
            client_key_path=self.client_key,
            expected_package_sha256="sha256:" + ("0" * 64),
            expected_public_key_sha256=self.fixture.key_digest,
            expected_trust_policy_sha256=self.fixture.trust_digest,
            expected_request_id="PILOT-INTEGRATION-001",
            expected_target="postgresql-prod/extension-slot-01",
            expected_evaluated_on=date(2026, 7, 29),
            verified_on=date(2026, 7, 29),
            idempotency_key="pilot-acceptance-offline-failure",
            openssl_path=self.fixture.openssl,
        )

        self.assertFalse(acceptance.accepted)
        self.assertIsNone(acceptance.document["event"])
        self.assertIsNone(
            acceptance.document["transport"]["server_certificate_sha256"]
        )
        self.assertEqual(
            {
                "id": "offline-enforcement",
                "status": "fail",
                "code": "offline-verification-failed",
            },
            acceptance.document["checks"][0],
        )
        self.assertEqual(
            ["not-run"] * 5,
            [
                check["status"]
                for check in acceptance.document["checks"][1:]
            ],
        )

    def test_rejects_client_private_key_with_broad_permissions(self) -> None:
        with TemporaryDirectory() as directory:
            unsafe_key = Path(directory) / "client-key.pem"
            shutil.copyfile(self.client_key, unsafe_key)
            unsafe_key.chmod(0o644)
            with self.assertRaisesRegex(
                PilotAcceptanceConfigurationError,
                "permissions",
            ):
                self._accept(client_key=unsafe_key)


if __name__ == "__main__":
    unittest.main()
