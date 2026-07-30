"""Static contracts for the hardened Admission Gateway deployments."""

from __future__ import annotations

from pathlib import Path
import unittest

from pgextassure._version import RELEASE_VERSION


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class GatewayDeploymentTests(unittest.TestCase):
    def test_container_runs_as_non_root_with_a_health_contract(self) -> None:
        dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertIn(
            "python:3.13-slim-bookworm@sha256:",
            dockerfile,
        )
        self.assertIn('VOLUME ["/var/lib/pgextassure"]', dockerfile)
        self.assertIn("HEALTHCHECK", dockerfile)
        self.assertIn("org.opencontainers.image.revision", dockerfile)
        self.assertIn("--require-hashes", dockerfile)
        self.assertIn("--only-binary=:all:", dockerfile)
        self.assertIn(
            'ENTRYPOINT ["pgextassure-gateway-entrypoint"]',
            dockerfile,
        )
        self.assertNotIn("PGEXTASSURE_LEDGER=", dockerfile)

    def test_entrypoint_creates_a_private_ledger_parent_and_execs(self) -> None:
        entrypoint = (
            PROJECT_ROOT / "docker" / "gateway-entrypoint.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('chmod 0700 "${state_dir}"', entrypoint)
        self.assertIn("exec pgextassure gateway serve", entrypoint)
        self.assertIn("--allow-remote", entrypoint)
        self.assertNotIn("private-key", entrypoint)

    def test_deployment_is_single_writer_and_default_deny_egress(
        self,
    ) -> None:
        manifest = (
            PROJECT_ROOT / "deploy" / "kubernetes.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("replicas: 1", manifest)
        self.assertIn("type: Recreate", manifest)
        self.assertIn("automountServiceAccountToken: false", manifest)
        self.assertIn("runAsNonRoot: true", manifest)
        self.assertIn("readOnlyRootFilesystem: true", manifest)
        self.assertIn("allowPrivilegeEscalation: false", manifest)
        self.assertIn("type: RuntimeDefault", manifest)
        self.assertIn("type: ClusterIP", manifest)
        self.assertIn("egress: []", manifest)
        self.assertNotIn("kind: Ingress", manifest)
        self.assertNotIn("type: LoadBalancer", manifest)
        self.assertIn(
            f"ghcr.io/borborich/pgextassure:{RELEASE_VERSION}",
            manifest,
        )

    def test_tagged_image_is_multi_platform_and_attested(self) -> None:
        workflow = (
            PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("docker/setup-qemu-action@", workflow)
        self.assertIn("platforms: linux/amd64,linux/arm64", workflow)
        self.assertIn("push-to-registry: true", workflow)
        self.assertIn("subject-digest:", workflow)
        self.assertIn("sbom: true", workflow)

    def test_tagged_helm_chart_is_packaged_and_attested(self) -> None:
        workflow = (
            PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('helm package "$chart"', workflow)
        self.assertIn("name: pgextassure-helm-chart", workflow)
        self.assertIn("helm-artifacts/*.tgz", workflow)
        self.assertIn("- helm-chart", workflow)
        self.assertIn(
            f"pgextassure-{RELEASE_VERSION}.tgz",
            workflow,
        )
        chart = (
            PROJECT_ROOT / "deploy" / "helm" / "pgextassure" / "Chart.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn(f"version: {RELEASE_VERSION}", chart)
        self.assertIn(f'appVersion: "{RELEASE_VERSION}"', chart)


if __name__ == "__main__":
    unittest.main()
