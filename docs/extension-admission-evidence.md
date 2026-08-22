# PostgreSQL extension admission needs portable evidence

PostgreSQL extensions are distributed like packages but admitted across a trust
boundary closer to plugins loaded by a privileged service. Their control files,
install and upgrade SQL, native libraries, and background-worker capabilities
can affect the database server and host in ways that ordinary application
dependencies cannot.

PostgreSQL's own `CREATE EXTENSION` documentation warns that extension
installation executes an extension's SQL script and that users must trust the
author unless the extension satisfies the trusted-extension conditions. The
question is therefore not merely whether an archive builds. It is why a
particular source snapshot is acceptable under a particular platform policy.

Reference: [PostgreSQL `CREATE EXTENSION`](https://www.postgresql.org/docs/current/sql-createextension.html).

## The missing artifact

Managed platforms already maintain extension catalogs and request processes:

- [Amazon RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Appendix.PostgreSQL.CommonDBATasks.Extensions.html)
  exposes supported extensions and an `rds.allowed_extensions` control;
- [Google Cloud SQL](https://docs.cloud.google.com/sql/docs/postgres/extensions?hl=en)
  permits only supported extensions and directs new requests through an issue
  process;
- [Supabase](https://supabase.com/docs/guides/database/extensions) publishes a
  configured extension set and accepts requests for additional extensions;
- [Neon](https://neon.com/blog/bring-your-own-extensions-to-serverless-postgresql)
  describes engineering review, compatibility work, builds, and security tests
  before onboarding requested extensions.

These are different implementations of the same decision. What is usually
missing from the exchange is a portable artifact that binds:

```text
pinned source
  + analyzer evidence
  + coverage and limitations
  + organization policy
  + human dispositions
  -> independently verifiable admission record
```

An allowlist records the final answer. It rarely preserves the exact evidence
and policy that produced it.

## Why a new scanner is not enough

The ecosystem already contains valuable specialists. `pgspot` performs
AST-based SQL and PL/pgSQL analysis. Aiven's `pghostile` and security agent
exercise or constrain runtime authority boundaries. Compatibility and upgrade
tools answer other parts of the admission question.

PgExtAssure does not claim to replace them. Its evidence model can normalize
external analyzer output, inventory package and native-code capabilities, bind
the result to exact source bytes, apply an organization-owned policy, and carry
the record forward for independent verification.

The durable interface should be the evidence, not one scanner's private score.

## Current public evidence

PgExtAssure alpha.16 is open source under Apache-2.0. Its disclosure-safe public
index processed 16 pinned projects and 2,114 files with alpha.15. Three external
operators have independently completed the alpha.16 reproduction workflow in
forks they control.

The exact runs and limitations are published in the
[public validation record](public-validation.md). These results establish
reproducibility of a bounded protocol, not production adoption, certification,
or complete security coverage.

## A practical adoption path

An extension maintainer can add the audit-only GitHub Action, retain a
machine-readable report, and optionally publish a verified evidence bundle with
a release. A platform reviewer can then apply its own policy and dispositions
without trusting an opaque hosted score or sending source to a new service.

The smallest useful ecosystem test is:

1. one maintainer publishes evidence for an exact release;
2. one independent reviewer verifies it;
3. one downstream team uses it as an input to a real intake decision;
4. the downstream team records what additional evidence was still required.

That final feedback is more important than another scanner feature. It reveals
whether portable admission evidence removes real work or merely relocates it.

## Try the bounded workflow

- [Add the GitHub Action](../README.md#github-action).
- [Run the independent reproduction](external-reproduction.md).
- [Inspect the public validation record](public-validation.md).
- [Request a bounded evaluation](founding-partner-evaluation.md) without an
  introductory meeting.

