# Admission Gateway deployment

This deployment profile runs the PgExtAssure Admission Gateway as a single,
non-root, stateful verifier. The gateway is not an Internet-facing API and does
not implement TLS, client authentication, or organization authorization.

## Security contract

The supplied container:

- runs as numeric UID/GID `65532`;
- starts only the gateway and includes no target package or private key;
- uses a read-only root filesystem in the supplied deployments;
- writes package bytes only to a bounded temporary filesystem;
- keeps the replay ledger on a separate persistent volume;
- creates the immediate ledger directory with mode `0700`;
- drops Linux capabilities and disables privilege escalation;
- has no vendor/package outbound client; optional PostgreSQL mode adds only the
  explicitly configured ledger connection;
- exposes liveness and readiness probes without disclosing ledger contents.

The image includes the OpenSSL executable used for the existing Corporate
Evidence Signature Profile. Public keys and Trust Policies remain inside the
Pilot Package; their expected digests still arrive through trusted request
headers.

## Build and inspect

Build from an exact, reviewed PgExtAssure revision:

```bash
docker build --pull --tag pgextassure-gateway:local .
docker image inspect pgextassure-gateway:local \
  --format '{{.Config.User}} {{json .Config.Healthcheck}}'
```

The checked-in build pins both its Dockerfile frontend and multi-platform
Python base-image digest. For a corporate rebuild, verify those anchors or
replace `PYTHON_IMAGE` with an independently approved digest:

```bash
docker build \
  --build-arg PYTHON_IMAGE='python:3.13-slim-bookworm@sha256:VERIFIED_DIGEST' \
  --tag registry.example/assurance/pgextassure@sha256:RESULT_DIGEST \
  .
```

Record and approve the resulting image digest. A source tag or mutable image
tag is not an admission anchor.

Tagged releases publish `linux/amd64` and `linux/arm64` images to GHCR under
both the Git tag and package version tags. The workflow attaches an SBOM and a
GitHub Sigstore build-provenance attestation. Verify the image before use:

```bash
gh attestation verify \
  oci://ghcr.io/borborich/pgextassure:0.1.0-alpha.13 \
  --repo borborich/pgextassure
```

## Docker Compose

The Compose profile publishes only on host loopback:

```bash
docker compose -f deploy/compose.yaml up --build
curl --fail http://127.0.0.1:8080/readyz
```

The named volume retains idempotency and request uniqueness across container
replacement. Removing or rolling back that volume removes those guarantees.

The supplied Compose and Kubernetes manifests remain conservative
single-writer SQLite examples. A PostgreSQL deployment sets
`PGEXTASSURE_POSTGRES_DSN_FILE` to a mode-`0600` mounted secret file, removes
the local ledger PVC requirement, permits egress only to the selected database
endpoint, and may then run multiple replicas. Do not open general egress.

For the digest-required multi-replica profile with mandatory TLS 1.3 client
authentication, use the [reference Helm chart](helm-deployment.md).

## Kubernetes

Before applying [`deploy/kubernetes.yaml`](../deploy/kubernetes.yaml):

1. publish the image to an organization-controlled registry;
2. replace the example tag with the verified image digest;
3. select a storage class that preserves the `ReadWriteOnce` ledger;
4. label only authorized in-cluster callers with
   `pgextassure.io/admission-client=true`;
5. place organization-owned mTLS/authentication in front of the ClusterIP
   Service when calls cross a trust boundary.

Then apply:

```bash
kubectl apply -f deploy/kubernetes.yaml
kubectl rollout status deployment/pgextassure-gateway
```

The example deliberately uses one replica and `Recreate`. PgExtAssure's SQLite
ledger is a single-writer local control. Do not scale this Deployment
horizontally or mount one ledger into multiple writers. PostgreSQL ledger mode
is the supported external strongly consistent uniqueness layer; its database
availability, backup, TLS, credentials, and recovery remain operator-owned.

## Backup, recovery, and upgrade

- Quiesce the gateway before taking a filesystem-level ledger backup.
- Encrypt backups and restrict them like deployment authorization records.
- Test restoration into an isolated gateway before relying on a backup.
- Never restore an older ledger over a newer production ledger: doing so can
  re-enable previously consumed request context.
- Roll forward with one replacement pod, retain the PVC, and verify `/readyz`
  before admitting requests.
- Treat ledger corruption as fail-closed. Preserve it for incident review and
  restore from the latest trusted non-rollback backup.

## Operational limits

The default maximum package size is 256 MiB, so the temporary filesystem is
300 MiB. The gateway accepts four concurrent requests with a 30-second socket
timeout. Tune those three values together with ingress body-size, connection,
CPU, memory, and ephemeral-storage limits. An upstream proxy must reject
requests before buffering more than the configured package boundary.

Do not place private signing keys, deployment credentials, or production
database credentials in the image, environment, ledger volume, or Pilot
Package. PostgreSQL credentials belong only in the private DSN secret file.
