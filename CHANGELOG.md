# Changelog

All notable user-visible changes to PgExtAssure will be documented in this
file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases use semantic versioning.

## [Unreleased]

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

[Unreleased]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.6...HEAD
[0.1.0-alpha.6]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.5...v0.1.0-alpha.6
[0.1.0-alpha.5]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.4...v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/borborich/pgextassure/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/borborich/pgextassure/releases/tag/v0.1.0-alpha.1
