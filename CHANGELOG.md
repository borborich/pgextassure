# Changelog

All notable user-visible changes to PgExtAssure will be documented in this
file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and releases use semantic versioning.

## [Unreleased]

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

[Unreleased]: https://github.com/borborich/pgextassure/commits/main
[0.1.0-alpha.1]: https://github.com/borborich/pgextassure/releases/tag/v0.1.0-alpha.1
