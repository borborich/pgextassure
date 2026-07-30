"""Static security contracts for the reference Helm deployment."""

from __future__ import annotations

from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CHART_ROOT = PROJECT_ROOT / "deploy" / "helm" / "pgextassure"


class HelmDeploymentContractTests(unittest.TestCase):
    def test_envoy_ingress_requires_tls13_client_authentication(self) -> None:
        config = (CHART_ROOT / "files" / "envoy.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("require_client_certificate: true", config)
        self.assertIn("tls_minimum_protocol_version: TLSv1_3", config)
        self.assertIn("tls_maximum_protocol_version: TLSv1_3", config)
        self.assertIn(
            "filename: /etc/pgextassure-mtls/ca.crt",
            config,
        )
        self.assertIn("address: 127.0.0.1", config)
        self.assertIn("port_value: 8080", config)
        self.assertNotIn("admin:", config)

    def test_chart_requires_digests_secrets_and_safe_ledger_modes(self) -> None:
        helpers = (CHART_ROOT / "templates" / "_helpers.tpl").read_text(
            encoding="utf-8"
        )
        values = (CHART_ROOT / "values.yaml").read_text(encoding="utf-8")
        smoke = (
            PROJECT_ROOT / "integration" / "mtls-gateway-smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("image.digest must be", helpers)
        self.assertIn("mtls.existingSecret is required", helpers)
        self.assertIn("SQLite ledger mode requires replicaCount=1", helpers)
        self.assertIn(
            "ledger.postgres.existingSecret is required",
            helpers,
        )
        self.assertIn("networkPolicy.postgresEgress is required", helpers)
        envoy_digest = (
            "sha256:"
            "7877ad87afd7459e1bd2a077ff601fec7c93aeecd62e71664560d96328c62cf4"
        )
        self.assertIn(envoy_digest, values)
        self.assertIn(envoy_digest, smoke)

    def test_gateway_is_loopback_only_and_service_exposes_only_mtls(self) -> None:
        deployment = (
            CHART_ROOT / "templates" / "deployment.yaml"
        ).read_text(encoding="utf-8")
        service = (CHART_ROOT / "templates" / "service.yaml").read_text(
            encoding="utf-8"
        )
        network_policy = (
            CHART_ROOT / "templates" / "networkpolicy.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("PGEXTASSURE_HOST", deployment)
        self.assertIn("value: 127.0.0.1", deployment)
        self.assertIn("runAsNonRoot: true", deployment)
        self.assertIn("readOnlyRootFilesystem: true", deployment)
        self.assertIn("allowPrivilegeEscalation: false", deployment)
        self.assertIn("automountServiceAccountToken: false", deployment)
        self.assertIn("name: mtls", service)
        self.assertNotIn("8080", service)
        self.assertIn("port: 8443", network_policy)
        self.assertNotIn("type: LoadBalancer", service)

    def test_postgres_secret_is_copied_to_private_runtime_file(self) -> None:
        deployment = (
            CHART_ROOT / "templates" / "deployment.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("name: prepare-postgres-dsn", deployment)
        self.assertIn("umask 077", deployment)
        self.assertIn("chmod 0600", deployment)
        self.assertIn("PGEXTASSURE_POSTGRES_DSN_FILE", deployment)
        self.assertIn("defaultMode: 0440", deployment)
        self.assertNotIn("valueFrom:", deployment)


if __name__ == "__main__":
    unittest.main()
