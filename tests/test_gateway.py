"""Loopback admission gateway and replay-ledger contracts."""

from __future__ import annotations

from http.client import HTTPConnection
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory, gettempdir
import threading
import unittest

from pgextassure.gateway import GatewayConfig, create_gateway_server
from tests.support import run_cli
from tests import test_enterprise as enterprise_module


class AdmissionGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        enterprise_module.EnterpriseAdmissionIntegrationTests.setUpClass()
        cls.fixture = enterprise_module.EnterpriseAdmissionIntegrationTests

    @classmethod
    def tearDownClass(cls) -> None:
        enterprise_module.EnterpriseAdmissionIntegrationTests.tearDownClass()

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(
            dir=Path(gettempdir()).resolve(),
        )
        self.root = Path(self.temporary.name)
        self.server = create_gateway_server(
            GatewayConfig(
                host="127.0.0.1",
                port=0,
                ledger_path=self.root / "admissions.sqlite3",
                maximum_request_bytes=8 * 1024 * 1024,
                maximum_concurrent_requests=2,
                request_timeout_seconds=5,
                openssl_path=self.fixture.openssl,
            )
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary.cleanup()

    def _headers(
        self,
        *,
        idempotency_key: str = "pilot-integration-001",
        package_digest: str | None = None,
    ) -> dict[str, str]:
        return {
            "Content-Type": "application/vnd.pgextassure.pilot+zip",
            "X-PgExtAssure-Package-SHA256": (
                package_digest or self.fixture.package_digest
            ),
            "X-PgExtAssure-Key-SHA256": self.fixture.key_digest,
            "X-PgExtAssure-Trust-Policy-SHA256": self.fixture.trust_digest,
            "X-PgExtAssure-Request-ID": "PILOT-INTEGRATION-001",
            "X-PgExtAssure-Target": "postgresql-prod/extension-slot-01",
            "X-PgExtAssure-Evaluated-On": "2026-07-29",
            "X-PgExtAssure-Verified-On": "2026-07-29",
            "Idempotency-Key": idempotency_key,
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection(self.host, self.port, timeout=10)
        try:
            connection.request(
                method,
                path,
                body=body,
                headers=headers or {},
            )
            response = connection.getresponse()
            raw = response.read()
            return response.status, dict(response.getheaders()), raw
        finally:
            connection.close()

    def test_health_readiness_and_unknown_route(self) -> None:
        health = self._request("GET", "/healthz")
        ready = self._request("GET", "/readyz")
        missing = self._request("GET", "/v1/missing")
        self.assertEqual(200, health[0])
        self.assertEqual({"status": "ok"}, json.loads(health[2]))
        self.assertEqual(200, ready[0])
        self.assertEqual({"status": "ready"}, json.loads(ready[2]))
        self.assertEqual(404, missing[0])
        self.assertEqual("not-found", json.loads(missing[2])["error"]["code"])

    def test_active_package_is_admitted_and_idempotently_replayed(self) -> None:
        package = self.fixture.package.read_bytes()
        first = self._request(
            "POST",
            "/v1/admissions",
            body=package,
            headers=self._headers(),
        )
        repeated = self._request(
            "POST",
            "/v1/admissions",
            body=package,
            headers=self._headers(),
        )
        conflict = self._request(
            "POST",
            "/v1/admissions",
            body=package,
            headers=self._headers(idempotency_key="different-key"),
        )
        self.assertEqual(200, first[0], first[2])
        self.assertEqual("false", first[1]["X-PgExtAssure-Replayed"])
        event = json.loads(first[2])
        self.assertEqual("allow", event["outcome"])
        self.assertEqual(first[2], repeated[2])
        self.assertEqual(200, repeated[0])
        self.assertEqual("true", repeated[1]["X-PgExtAssure-Replayed"])
        self.assertEqual(409, conflict[0])
        self.assertEqual(
            "replay-conflict",
            json.loads(conflict[2])["error"]["code"],
        )

    def test_tampered_ledger_event_fails_as_an_internal_error(self) -> None:
        package = self.fixture.package.read_bytes()
        first = self._request(
            "POST",
            "/v1/admissions",
            body=package,
            headers=self._headers(),
        )
        self.assertEqual(200, first[0], first[2])
        ledger = sqlite3.connect(self.root / "admissions.sqlite3")
        try:
            ledger.execute(
                "UPDATE admissions SET event_json = ?",
                (sqlite3.Binary(b'{"tampered":true}\n'),),
            )
            ledger.commit()
        finally:
            ledger.close()
        repeated = self._request(
            "POST",
            "/v1/admissions",
            body=package,
            headers=self._headers(),
        )
        self.assertEqual(500, repeated[0])
        self.assertEqual(
            "internal-error",
            json.loads(repeated[2])["error"]["code"],
        )

    def test_bad_request_and_integrity_failure_have_distinct_statuses(
        self,
    ) -> None:
        package = self.fixture.package.read_bytes()
        missing = self._request(
            "POST",
            "/v1/admissions",
            body=package,
            headers={"Content-Type": "application/octet-stream"},
        )
        wrong_digest = self._request(
            "POST",
            "/v1/admissions",
            body=package,
            headers=self._headers(
                package_digest="sha256:" + "0" * 64,
            ),
        )
        self.assertEqual(400, missing[0])
        self.assertEqual(
            "invalid-request",
            json.loads(missing[2])["error"]["code"],
        )
        self.assertEqual(422, wrong_digest[0])
        self.assertEqual(
            "admission-verification-failed",
            json.loads(wrong_digest[2])["error"]["code"],
        )

    def test_ledger_permissions_and_remote_bind_are_fail_closed(self) -> None:
        mode = (self.root / "admissions.sqlite3").stat().st_mode & 0o777
        remote = run_cli(
            "gateway",
            "serve",
            "--host",
            "0.0.0.0",
            "--port",
            "0",
            "--ledger",
            str(self.root / "other.sqlite3"),
        )
        broad = self.root / "broad.sqlite3"
        broad.write_bytes(b"")
        os.chmod(broad, 0o644)
        broad_result = run_cli(
            "gateway",
            "serve",
            "--port",
            "0",
            "--ledger",
            str(broad),
        )
        self.assertEqual(0o600, mode)
        self.assertEqual(2, remote.returncode)
        self.assertIn("requires explicit --allow-remote", remote.stderr)
        self.assertEqual(2, broad_result.returncode)
        self.assertIn("permissions", broad_result.stderr)


if __name__ == "__main__":
    unittest.main()
