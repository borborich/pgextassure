# Changelog

All notable user-visible changes to PgExtAssure will be documented in this
file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases use semantic versioning.

## [Unreleased]

## [0.1.0-alpha.17] - 2026-08-22

### Added

- Public, immutable external-reproduction workflow and disclosure-safe report
  path for independent verification of the alpha.16 protocol.
- Public validation record documenting multiple independent successful
  reproductions without claiming certification, customer adoption, or
  employer endorsement.
- Self-service Founding Partner Evaluation, sample readiness report, and
  extension-admission evidence rationale for asynchronous enterprise
  evaluation.

### Changed

- GitHub and package metadata now point evaluators to the PgExtAssure product
  site and documentation.
- The primary adoption path is a customer-controlled GitHub Action with
  portable evidence rather than a mandatory introductory meeting.

## [0.1.0-alpha.16] - 2026-08-07

### Added

- Fail-closed pgspot `0.9.2` text adapter with deterministic, digest-bound
  External Analysis `1.0` documents and independent source/stdout
  recomputation.
- Published External Analysis JSON Schema and explicit observational-only
  trust boundary that leaves admission policy and Evidence Bundle `1.0`
  unchanged.
- Separate medium-severity review signals for `SECURITY DEFINER` routines with
  runtime `search_path` logic or only plainly schema-qualified calls, and for
  event-trigger callbacks that are not ordinary callable APIs.

### Changed

- High-confidence `SECURITY DEFINER` search-path findings now require an
  unqualified callable lookup when the declaration has no recognized safe
  path; ambiguous body-level cases remain visible without asserting an
  exploit.
- PUBLIC-execute findings explicitly describe an exposed definer authority
  boundary without claiming that every such routine is a privilege escalation.

### Fixed

- External-connection findings no longer treat routine names mentioned only by
  `ALTER` or `DROP` as newly introduced outbound-network capability; routine
  declarations and real calls remain detectable.

## [0.1.0-alpha.15] - 2026-07-30

### Fixed

- Corrupt DEFLATE streams in Pilot Packages and Evidence Bundles now fail
  closed with the documented verification exit code instead of exposing a
  Python traceback.

## [0.1.0-alpha.14] - 2026-07-30

### Added

- Self-service `pilot accept` runner for offline package enforcement, TLS 1.3
  readiness, negative mTLS/TLS 1.2 checks, first admission, and byte-identical
  replay without Kubernetes access or a manual demo.
- Closed Pilot Acceptance Report `1.0` with ordered pass/fail/not-run checks,
  canonical bytes, hashed idempotency and mTLS certificate identities, and no
  TLS secret paths.

## [0.1.0-alpha.13] - 2026-07-30

### Added

- Optional PostgreSQL Admission Gateway ledger with schema-version validation,
  global idempotency/request-context uniqueness, transaction-scoped advisory
  locks, and exact byte replay across multiple gateway instances.
- Private DSN-file configuration, explicit least-privilege schema bootstrap,
  reproducible Psycopg dependencies, and a pinned PostgreSQL concurrency CI
  contract.
- Digest-required Helm profiles for single-writer SQLite and multi-replica
  PostgreSQL, with mandatory Envoy TLS 1.3 client authentication, loopback-only
  gateway binding, least-privilege Secret handling, and database-only egress.
- Full HTTP concurrency coverage across two gateway servers sharing one
  PostgreSQL ledger.

## [0.1.0-alpha.12] - 2026-07-29

### Added

- Credential-free Admission Event projections for Jira Cloud REST API v3,
  ServiceNow Change Request Table API, Splunk HEC, and Elastic Bulk API.
- Canonical Integration Export Manifest `1.0` binding vendor payload bytes,
  HTTP request metadata, and the exact source Admission Event.
- Strict Admission Event input verification including canonical JSON,
  duplicate-key rejection, semantic consistency, and event-ID recomputation.
- Loopback-first Admission Gateway with bounded binary requests, health and
  readiness endpoints, fail-closed HTTP semantics, and no outbound client.
- Mode-0600 SQLite replay/idempotency ledger binding unique request context,
  package digest, exact event bytes, and event SHA-256.
- Closed Admission Gateway Error schema `1.0`.
- Rootless Admission Gateway container with read-only-root deployment profiles,
  persistent ledger storage, bounded temporary storage, probes, resource
  limits, and default-deny Kubernetes egress.
- Single-writer Docker Compose and Kubernetes examples plus an operator
  deployment, backup, recovery, and upgrade runbook.

## [0.1.0-alpha.11] - 2026-07-29

### Added

- One-shot Enterprise Pilot Package enforcement against out-of-band package,
  public-key, Trust Policy, and request-context anchors.
- Closed Admission Event `1.0` for CI, Jira, ServiceNow, and SIEM ingestion,
  plus a dedicated GitHub admission sub-action.

## [0.1.0-alpha.10] - 2026-07-29

### Added

- Enterprise Pilot Package `1.0` with a deterministic flat ZIP, canonical
  payload manifest, exact release-distribution checksum validation,
  non-extracting offline verification, and private-key marker rejection.

## [0.1.0-alpha.9] - 2026-07-29

### Added

- Enterprise Trust Policy `1.0` with exact signer fingerprints,
  validity/revocation windows, tool/ruleset/evidence-policy constraints, and
  evidence/signature age limits.
- Deterministic Admission Receipt `1.0` with closed deny reasons, bounded
  request context, expiry, offline recomputation, and explicit active/inactive
  enforcement.

## [0.1.0-alpha.8] - 2026-07-29

### Added

- Corporate Evidence Signature Profile `1.0` with offline detached
  RSA-PSS-SHA256 signing, minimum 3072-bit keys, canonical bundle-bound
  statements, and fail-closed independent verification.
- Transferable enterprise pilot kit with a thirty-minute acceptance path,
  objective acceptance criteria, independent verification steps, and security
  questionnaire answers.

## [0.1.0-alpha.7] - 2026-07-29

### Added

- Digest-bound Scope Plan `1.0` with non-overlapping relative roots and exact
  SHA-256-pinned regular-file and symlink exclusions.
- Scope provenance in regular/grouped reports, Evidence Bundle materials,
  composite Action inputs, and the reproducible public-corpus runner.

### Changed

- **Breaking for JSON consumers:** regular reports now use schema `1.4` and
  grouped reports use schema `1.3`.

## [0.1.0-alpha.6] - 2026-07-29

### Added

- Deterministic Agent Review Pack `1.0` output with exact grouped-report and
  source-manifest digests, one task per root cause, a closed disposition
  vocabulary, and an explicit no-admission-authority contract.
- Offline-created and verified Agent Review Decision Ledger `1.0` with exact
  pack/task correlation and mandatory evidence for resolved dispositions.

### Fixed

- Correlation of named/default PostgreSQL routine declarations with
  identity-argument signatures used by exact `REVOKE ... FROM PUBLIC`
  statements.

## [0.1.0-alpha.5] - 2026-07-29

### Added

- Deterministic Evidence Bundle `1.0` creation with canonical report, exact
  admission-control inputs, and a bounded SPDX 2.3 analyzed-source inventory.
- Non-extracting offline evidence verification with archive, digest,
  manifest, coverage, control-input, and SPDX consistency checks.
- Composite Action evidence mode and a strict enterprise pilot workflow using
  pinned GitHub/Sigstore custom and SBOM attestations.
- Tag-only SLSA provenance attestations for future release wheel and sdist
  artifacts.

## [0.1.0-alpha.4] - 2026-07-29

### Added

- Bounded, escaped GitHub workflow annotations grouped by root cause, with
  active-only and all-dispositions modes and no matched source evidence.
- Packaged `adoption` and `strict` organization policy templates, available
  through the new `policy-template` command.

## [0.1.0-alpha.3] - 2026-07-29

### Added

- Regular report schema `1.3` and grouped report schema `1.2` with a
  deterministic, bounded skipped-file coverage inventory.
- Draft 2020-12 JSON Schemas for reports, generation plans, baselines,
  suppressions, and organization policy files.
- Strict ruleset-bound organization policies with severity, exact
  capability/rule gates, and admission-mechanism controls.
- Ruleset-bound root-cause baselines for introducing a CI gate without hiding
  existing findings.
- Exact, owner-attributed suppressions with required reasons and inclusive
  expiry dates; expired exceptions block again.
- Admission provenance and dispositions in JSON, grouped JSON, SARIF, text,
  and the composite GitHub Action.

### Changed

- **Breaking for JSON consumers:** regular reports now use schema `1.3` and
  grouped reports use schema `1.2`; consumers should validate against the
  published versioned JSON Schemas.

## [0.1.0-alpha.2] - 2026-07-29

### Added

- Conservative `grouped-json` reports with stable root-cause identifiers,
  complete occurrence locations, and separate finding/root-cause counts.
- Routine-identity evidence for unsafe `SECURITY DEFINER` search paths.
- Root-cause counts in the reproducible public-corpus runner.
- Strict generation-plan schema for pinned virtual SQL artifacts and
  in-memory literal rendering of control/SQL templates without executing a
  build.
- Generation-plan provenance in JSON, grouped JSON, SARIF, and text reports,
  plus GitHub Action support.

### Changed

- Updated the pinned `actions/checkout` and `actions/setup-python` runtimes to
  their reviewed v7 releases.

## [0.1.0-alpha.1] - 2026-07-28

### Added

- Static scanning for PostgreSQL extension control, SQL, C, header, Rust, and
  Cargo manifest inputs.
- Install and upgrade graph checks.
- Deterministic text, JSON, and SARIF reports.
- Configurable severity-based exit behavior.
- Composite GitHub Action with audit-only defaults.
- Public rule reference, threat model, roadmap, contribution guide, support
  guide, and security policy.
- Fail-closed handling for empty, unreadable, symlinked, non-regular, binary,
  non-UTF-8, oversized, path/depth/entry-flood, included-control, and
  ambiguous-scope inputs.
- Atomic report writes, terminal-safe text output, repository-relative SARIF
  locations, isolated Action execution, version-specific control inheritance,
  configured script-directory resolution, and adversarial parser/graph
  hardening across CR/LF, dollar-quote, Unicode-identifier, and UESCAPE forms.
- Gate-preserving broken-pipe handling and stricter `pg_temp` placement for
  recognized safe `SECURITY DEFINER` search paths.

[Unreleased]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.17...HEAD
[0.1.0-alpha.17]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.16...v0.1.0-alpha.17
[0.1.0-alpha.16]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.15...v0.1.0-alpha.16
[0.1.0-alpha.15]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.14...v0.1.0-alpha.15
[0.1.0-alpha.14]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.13...v0.1.0-alpha.14
[0.1.0-alpha.13]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.12...v0.1.0-alpha.13
[0.1.0-alpha.12]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.11...v0.1.0-alpha.12
[0.1.0-alpha.11]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.10...v0.1.0-alpha.11
[0.1.0-alpha.10]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.9...v0.1.0-alpha.10
[0.1.0-alpha.9]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.8...v0.1.0-alpha.9
[0.1.0-alpha.8]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.7...v0.1.0-alpha.8
[0.1.0-alpha.7]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.6...v0.1.0-alpha.7
[0.1.0-alpha.6]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.5...v0.1.0-alpha.6
[0.1.0-alpha.5]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.4...v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/borborich/pgextassure/releases/tag/v0.1.0-alpha.1
