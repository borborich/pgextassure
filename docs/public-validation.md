# Public validation record

PgExtAssure publishes the evidence that can be checked independently and keeps
its limits explicit. This page is a validation ledger, not a list of
endorsements.

## Current claim

> PgExtAssure alpha.16 has been independently reproduced by multiple external
> software engineers.

The claim means that independent operators ran the project's unmodified,
digest-bound workflow in forks they controlled and GitHub recorded a successful
result. It does **not** mean that PgExtAssure is certified, production-proven,
adopted by the operators' employers, or endorsed by them.

## Independent reproductions

All three runs used the unmodified protocol revision
[`ed8e0b1394717764b9d755c2616b7f90b47364cd`](https://github.com/borborich/pgextassure/commit/ed8e0b1394717764b9d755c2616b7f90b47364cd).
The protocol itself pins the alpha.16 implementation and PostgreSQL container
by immutable digest.

| Date (UTC) | Independent operator | Result | Public record |
| --- | --- | --- | --- |
| 2026-08-12 | `superheher` | Passed | [Workflow run](https://github.com/superheher/pgextassure/actions/runs/31573049905) · [submitted report #45](https://github.com/borborich/pgextassure/issues/45) |
| 2026-08-18 | `rednikotin` | Passed | [Workflow run](https://github.com/rednikotin/pgextassure/actions/runs/32168358991) |
| 2026-08-19 | `vlasovilya` | Passed | [Workflow run](https://github.com/vlasovilya/pgextassure/actions/runs/32227933620) · [submitted report #46](https://github.com/borborich/pgextassure/issues/46) |

The workflow verifies a deterministic scanner evidence artifact and two
controlled PostgreSQL authority-boundary semantics. It does not execute a
third-party extension. See the complete
[external reproduction protocol](external-reproduction.md).

## Public corpus

The disclosure-safe
[Extension Assurance Index](../benchmarks/public-corpus/index/2026-08-05-alpha15/index.md)
records that alpha.15 processed 16 pinned public projects and 2,114 files. It
publishes provenance, coverage, and capability profiles while withholding
project-specific findings pending review and coordinated disclosure where
appropriate.

A processed project is not a security rating, approval, certification, or
maintainer endorsement.

## What remains unproven

As of 2026-08-22, PgExtAssure does not claim:

- production customer adoption;
- a security, compliance, or regulatory certification;
- complete vulnerability discovery or absence of vulnerabilities;
- that a clean result is sufficient to admit an extension;
- independent review of every rule or of the complete implementation;
- measured commercial value in a real organizational admission workflow.

The next validation milestone is a design partner using PgExtAssure evidence in
an actual, organization-owned extension intake decision.

## Reproduce it yourself

The public workflow takes approximately 15 minutes of unattended GitHub Actions
time. Follow [Independent external reproduction](external-reproduction.md) and
report successful **or failed** outcomes. Failure reports are useful and remain
part of the validation record.

