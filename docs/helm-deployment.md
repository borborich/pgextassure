# Helm deployment with mandatory mTLS

The reference chart at
[`deploy/helm/pgextassure`](../deploy/helm/pgextassure) deploys the Admission
Gateway behind an Envoy sidecar that requires a client certificate signed by
the configured corporate CA. The gateway binds only to pod loopback. The
ClusterIP Service and NetworkPolicy expose only Envoy's TLS port `8443`.

The chart intentionally fails to render until both an independently verified
PgExtAssure image digest and an existing mTLS Secret are supplied. It never
generates a CA, server key, client key, PostgreSQL credential, or mutable image
reference.

The bundled Envoy `1.39.0` distroless sidecar is referenced by its verified
multi-platform image digest, not by a mutable tag.

## Required mTLS Secret

Issue the server certificate and client certificates through the
organization's existing PKI. The server certificate must cover the DNS name
clients use for the Service. Create the namespaced Secret without putting
private keys in a values file or source control:

```bash
kubectl create secret generic pgextassure-mtls \
  --from-file=ca.crt=corporate-client-ca.pem \
  --from-file=tls.crt=pgextassure-server-chain.pem \
  --from-file=tls.key=pgextassure-server-key.pem
```

Envoy accepts TLS 1.3 only, requires a client certificate, and validates it
against `ca.crt`. Possession of a certificate signed by that CA is the
authorization boundary in this reference profile. Use a dedicated client CA
or constrain certificate issuance to the intended callers.

## SQLite profile

SQLite is the default and is deliberately restricted to one replica with a
`Recreate` strategy and a `ReadWriteOnce` PVC:

```bash
helm upgrade --install pgextassure deploy/helm/pgextassure \
  --namespace pgextassure \
  --create-namespace \
  --set-string image.digest='sha256:VERIFIED_ALPHA13_IMAGE_DIGEST' \
  --set mtls.existingSecret=pgextassure-mtls
```

The chart rejects `replicaCount` values other than `1` in this mode.

## PostgreSQL profile

Provision ledger schema 1 with
[`deploy/postgres-ledger.sql`](../deploy/postgres-ledger.sql), then remove DDL
rights from the runtime role. Create the DSN Secret:

```bash
kubectl create secret generic pgextassure-postgres \
  --from-file=dsn=postgres.dsn
```

The init container copies that projected Secret into a private mode-`0600`
file. The DSN is never passed as a command-line value or placed in Helm values.

Create an operator-owned values file defining the replicas and exact permitted
database egress. This example uses an IP block; a namespace/pod selector may be
used for an in-cluster database:

```yaml
replicaCount: 2
ledger:
  mode: postgres
  postgres:
    existingSecret: pgextassure-postgres
mtls:
  existingSecret: pgextassure-mtls
networkPolicy:
  postgresEgress:
    - to:
        - ipBlock:
            cidr: 192.0.2.10/32
      ports:
        - protocol: TCP
          port: 5432
```

Install with the verified release digest:

```bash
helm upgrade --install pgextassure deploy/helm/pgextassure \
  --namespace pgextassure \
  --create-namespace \
  --values postgres-values.yaml \
  --set-string image.digest='sha256:VERIFIED_ALPHA13_IMAGE_DIGEST'
```

PostgreSQL mode uses `RollingUpdate`, a PodDisruptionBudget when replicas are
greater than one, and the supplied database-only egress rules. DNS egress is
not opened automatically. If the DSN uses a hostname, explicitly add only the
organization's required DNS path or prefer a stable database IP/service
selector.

## Verify the boundary

Forward the TLS Service and test with corporate client credentials:

```bash
kubectl port-forward service/pgextassure 8443:8443

curl --fail \
  --tlsv1.3 \
  --cacert corporate-server-ca.pem \
  --cert authorized-client.pem \
  --key authorized-client-key.pem \
  https://localhost:8443/readyz
```

The same request without a client certificate or with a certificate from an
untrusted CA must fail during the TLS handshake. Direct gateway port `8080` is
not published and is blocked by the NetworkPolicy.

## Upgrade rules

- Verify and record every PgExtAssure and Envoy image digest.
- Keep `ledger.postgres.initialize=false` during normal operation.
- Upgrade schema under a separate migration role before rolling application
  pods.
- Do not roll back a ledger or restore an older snapshot over newer admission
  records.
- Rotate the server certificate and client CA through a reviewed Secret
  update, then restart pods and retest both accepted and rejected clients.
- Restart pods after rotating the PostgreSQL DSN Secret; the private runtime
  copy is intentionally created only during pod initialization.
