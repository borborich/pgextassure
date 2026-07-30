"""PostgreSQL admission-ledger security and concurrency contracts."""

from __future__ import annotations

from http.client import HTTPConnection
import os
from pathlib import Path
from tempfile import TemporaryDirectory, gettempdir
import threading
import time
import unittest

from pgextassure.gateway import (
    GatewayConfig,
    GatewayConflict,
    GatewayError,
    PostgreSQLAdmissionLedger,
    _advisory_lock_key,
    _read_postgres_dsn,
    create_gateway_server,
    validate_gateway_config,
)
from tests import test_enterprise as enterprise_module


class PostgreSQLLedgerConfigurationTests(unittest.TestCase):
    def test_config_requires_exactly_one_ledger(self) -> None:
        with self.assertRaisesRegex(GatewayError, "exactly one ledger"):
            validate_gateway_config(GatewayConfig(host="127.0.0.1", port=0))
        with TemporaryDirectory(dir=Path(gettempdir()).resolve()) as temporary:
            with self.assertRaisesRegex(GatewayError, "initialization requires"):
                validate_gateway_config(
                    GatewayConfig(
                        host="127.0.0.1",
                        port=0,
                        ledger_path=Path(temporary) / "admissions.sqlite3",
                        initialize_postgres_ledger=True,
                    )
                )

    def test_dsn_secret_is_private_regular_single_line_file(self) -> None:
        with TemporaryDirectory(dir=Path(gettempdir()).resolve()) as temporary:
            root = Path(temporary)
            secret = root / "postgres.dsn"
            secret.write_text("postgresql://gateway@db/assurance\n", encoding="utf-8")
            os.chmod(secret, 0o600)
            validated = validate_gateway_config(
                GatewayConfig(
                    host="127.0.0.1",
                    port=0,
                    postgres_dsn_file=secret,
                )
            )
            self.assertEqual(secret.resolve(), validated.postgres_dsn_file)
            self.assertEqual(
                "postgresql://gateway@db/assurance",
                _read_postgres_dsn(secret),
            )
            os.chmod(secret, 0o644)
            with self.assertRaisesRegex(GatewayError, "permissions"):
                validate_gateway_config(
                    GatewayConfig(
                        host="127.0.0.1",
                        port=0,
                        postgres_dsn_file=secret,
                    )
                )

    def test_advisory_keys_are_stable_signed_bigints(self) -> None:
        first = _advisory_lock_key("idempotency:pilot-001")
        self.assertEqual(first, _advisory_lock_key("idempotency:pilot-001"))
        self.assertNotEqual(first, _advisory_lock_key("context:pilot-001"))
        self.assertGreaterEqual(first, -(2**63))
        self.assertLess(first, 2**63)


@unittest.skipUnless(
    os.environ.get("PGEXTASSURE_TEST_POSTGRES_DSN_FILE"),
    "requires PGEXTASSURE_TEST_POSTGRES_DSN_FILE",
)
class PostgreSQLLedgerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dsn_file = Path(
            os.environ["PGEXTASSURE_TEST_POSTGRES_DSN_FILE"]
        )
        cls.first = PostgreSQLAdmissionLedger(cls.dsn_file, initialize=True)
        cls.second = PostgreSQLAdmissionLedger(cls.dsn_file)

    def setUp(self) -> None:
        connection = self.first._connect()
        try:
            connection.cursor().execute(
                "TRUNCATE TABLE pgextassure_admissions"
            )
            connection.commit()
        finally:
            connection.close()

    def test_two_instances_execute_once_and_replay_exact_bytes(self) -> None:
        start = threading.Barrier(2)
        operation_lock = threading.Lock()
        operation_count = 0
        results = []
        errors = []

        def operation() -> tuple[bytes, int]:
            nonlocal operation_count
            with operation_lock:
                operation_count += 1
            time.sleep(0.1)
            return b'{"outcome":"allow"}\n', 200

        def admit(ledger: PostgreSQLAdmissionLedger) -> None:
            try:
                start.wait(timeout=5)
                results.append(
                    ledger.execute(
                        idempotency_key="shared-idempotency-key",
                        request_id="CHG-ALPHA13-001",
                        target="postgresql-prod/extension-slot-01",
                        package_digest="sha256:" + "a" * 64,
                        operation=operation,
                    )
                )
            except BaseException as error:
                errors.append(error)

        threads = [
            threading.Thread(target=admit, args=(self.first,)),
            threading.Thread(target=admit, args=(self.second,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual([], errors)
        self.assertEqual(1, operation_count)
        self.assertEqual(2, len(results))
        self.assertEqual([False, True], sorted(result.replayed for result in results))
        self.assertEqual(1, len({result.event for result in results}))

    def test_request_context_is_globally_unique(self) -> None:
        self.first.execute(
            idempotency_key="first-key",
            request_id="CHG-ALPHA13-002",
            target="postgresql-prod/extension-slot-02",
            package_digest="sha256:" + "b" * 64,
            operation=lambda: (b'{"outcome":"allow"}\n', 200),
        )
        with self.assertRaises(GatewayConflict):
            self.second.execute(
                idempotency_key="second-key",
                request_id="CHG-ALPHA13-002",
                target="postgresql-prod/extension-slot-02",
                package_digest="sha256:" + "b" * 64,
                operation=lambda: (b"must-not-run", 200),
            )


@unittest.skipUnless(
    os.environ.get("PGEXTASSURE_TEST_POSTGRES_DSN_FILE"),
    "requires PGEXTASSURE_TEST_POSTGRES_DSN_FILE",
)
class PostgreSQLGatewayIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        enterprise_module.EnterpriseAdmissionIntegrationTests.setUpClass()
        cls.fixture = enterprise_module.EnterpriseAdmissionIntegrationTests
        cls.dsn_file = Path(
            os.environ["PGEXTASSURE_TEST_POSTGRES_DSN_FILE"]
        )
        cls.ledger = PostgreSQLAdmissionLedger(cls.dsn_file, initialize=True)

    @classmethod
    def tearDownClass(cls) -> None:
        enterprise_module.EnterpriseAdmissionIntegrationTests.tearDownClass()

    def setUp(self) -> None:
        connection = self.ledger._connect()
        try:
            connection.cursor().execute(
                "TRUNCATE TABLE pgextassure_admissions"
            )
            connection.commit()
        finally:
            connection.close()
        self.servers = [
            create_gateway_server(
                GatewayConfig(
                    host="127.0.0.1",
                    port=0,
                    postgres_dsn_file=self.dsn_file,
                    maximum_request_bytes=8 * 1024 * 1024,
                    maximum_concurrent_requests=2,
                    request_timeout_seconds=5,
                    openssl_path=self.fixture.openssl,
                )
            )
            for _index in range(2)
        ]
        self.threads = [
            threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.05},
                daemon=True,
            )
            for server in self.servers
        ]
        for thread in self.threads:
            thread.start()

    def tearDown(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=5)

    def _headers(self, idempotency_key: str) -> dict[str, str]:
        return {
            "Content-Type": "application/vnd.pgextassure.pilot+zip",
            "X-PgExtAssure-Package-SHA256": self.fixture.package_digest,
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
        server_index: int,
        idempotency_key: str,
    ) -> tuple[int, dict[str, str], bytes]:
        host, port = self.servers[server_index].server_address[:2]
        connection = HTTPConnection(host, port, timeout=15)
        try:
            package = self.fixture.package.read_bytes()
            connection.request(
                "POST",
                "/v1/admissions",
                body=package,
                headers=self._headers(idempotency_key),
            )
            response = connection.getresponse()
            return (
                response.status,
                dict(response.getheaders()),
                response.read(),
            )
        finally:
            connection.close()

    def test_two_http_gateways_share_exact_replay_boundary(self) -> None:
        start = threading.Barrier(2)
        results = []
        errors = []

        def admit(server_index: int) -> None:
            try:
                start.wait(timeout=5)
                results.append(
                    self._request(server_index, "shared-http-key")
                )
            except BaseException as error:
                errors.append(error)

        threads = [
            threading.Thread(target=admit, args=(0,)),
            threading.Thread(target=admit, args=(1,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        self.assertEqual([], errors)
        self.assertEqual([200, 200], sorted(result[0] for result in results))
        self.assertEqual(
            ["false", "true"],
            sorted(result[1]["X-PgExtAssure-Replayed"] for result in results),
        )
        self.assertEqual(1, len({result[2] for result in results}))

    def test_context_conflict_is_shared_between_http_gateways(self) -> None:
        first = self._request(0, "first-http-key")
        conflict = self._request(1, "second-http-key")
        self.assertEqual(200, first[0])
        self.assertEqual(409, conflict[0])


if __name__ == "__main__":
    unittest.main()
