# PgExtAssure Helm chart

This chart deploys the PgExtAssure Admission Gateway behind mandatory Envoy
TLS 1.3 client authentication. It supports a one-replica SQLite ledger or a
shared PostgreSQL ledger with multiple replicas.

The chart deliberately requires an existing mTLS Secret and an independently
verified PgExtAssure image digest. See the complete
[deployment and PKI runbook](../../../docs/helm-deployment.md) before
rendering or installing it.
