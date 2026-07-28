# PgExtAssure

**Static pre-admission security assurance for PostgreSQL extensions.**

PgExtAssure inspects an extension source tree before a platform team allowlists,
builds, or installs it. It reads PostgreSQL extension metadata and source files,
reports security-relevant patterns, and can fail CI at a chosen severity.

It does **not** build, load, install, or execute the extension it scans.

> PgExtAssure produces review evidence, not a certificate. A clean report is not
> proof that an extension is safe, and it is not legal, compliance, or security
> advice.

Canonical repository: <https://github.com/borborich/pgextassure>

The command-line executable and Python module are both named `pgextassure`.

## The problem

Installing a PostgreSQL extension can cross unusually powerful trust
boundaries. Installation and upgrade scripts may run with elevated database
privileges; native modules may execute inside the PostgreSQL server process;
and a `trusted` or allowlisted extension can expose those capabilities to users
who are not superusers.

The admission decision is therefore difficult to review consistently:

- source packages mix control metadata, install SQL, upgrade SQL, and native
  code;
- reviewers need a repeatable inventory before they spend time on manual
  analysis;
- conventional database linters inspect an existing database, after the
  extension has already crossed the admission boundary;
- an allowlist says *what may be installed*, but does not explain why an entry
  is safe enough to allow.

PgExtAssure puts a deterministic, reviewable static gate before that decision.

## Two-minute quickstart

From a clone of this repository:

```bash
git clone https://github.com/borborich/pgextassure.git
cd pgextassure
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .

pgextassure scan /path/to/postgres-extension \
  --format text \
  --fail-on high
```

Equivalent module invocation:

```bash
python -m pgextassure scan /path/to/postgres-extension
```

Write a machine-readable report without blocking the current run:

```bash
pgextassure scan /path/to/postgres-extension \
  --format json \
  --output pgextassure.json \
  --fail-on none
```

For a compact review queue that preserves every source location while grouping
only findings with a proven shared routine identity:

```bash
pgextassure scan /path/to/postgres-extension \
  --format grouped-json \
  --output pgextassure-grouped.json \
  --fail-on none
```

`grouped-json` is a separate report type, so the existing JSON v1 and SARIF
contracts remain unchanged. Its summary reports both raw finding count and
root-cause count. Rules without an explicit semantic identity remain
location-scoped and are never merged heuristically.

Exit behavior is controlled by `--fail-on`:

```text
critical | high | medium | low | none
```

The process exits non-zero when at least one finding meets or exceeds the
selected threshold. Scanner errors also exit non-zero.

## Example finding

The exact rendering may evolve, but every format carries the same core
evidence: rule identifier, severity, location, explanation, and remediation.

```text
CRITICAL  sql.security-definer-search-path
      sql/example--1.0.sql:42

SECURITY DEFINER function does not establish a constrained search_path.
An attacker may be able to redirect an unqualified object reference.

Evidence:
  CREATE FUNCTION example.refresh_cache() ...
  SECURITY DEFINER;

Remediation:
  Set a safe search_path and schema-qualify referenced objects. Review the
  function against PostgreSQL's SECURITY DEFINER guidance.
```

Example summary:

```text
PgExtAssure 0.1.0-alpha.1
Manifest: sha256:93c7a1aa82da96c290155124b31fcfaa15e369d105cef327c38c17e1b82d8128
Files: 6 | Findings: 0 (critical 0, high 0, medium 0, low 0)
```

Findings identify review work; they do not establish exploitability.

## GitHub Action

The repository includes a composite Action that installs the local PgExtAssure
package and scans the requested path. The target extension is never executed.

```yaml
name: PgExtAssure

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0

      - uses: borborich/pgextassure@v0.1.0-alpha.1
        with:
          path: .
          format: sarif
          output: pgextassure.sarif
          fail-on: high

      - name: Upload SARIF
        if: ${{ always() && github.event_name != 'pull_request' }}
        uses: github/codeql-action/upload-sarif@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81 # v4.37.3
        with:
          sarif_file: pgextassure.sarif
```

Action inputs:

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Extension source directory or supported input file |
| `format` | `sarif` | `text`, `json`, `grouped-json`, or `sarif` |
| `output` | `pgextassure.sarif` | Report file; set to an empty string for stdout |
| `fail-on` | `none` | Minimum blocking severity, or `none` |
| `python-version` | `3.11` | Python used to run PgExtAssure |

Pin a released commit SHA in higher-assurance workflows. Uploading SARIF sends
the generated report to GitHub; review your repository visibility, retention,
and access settings before enabling that step. The example uploads only on
non-PR events because fork pull requests receive a read-only token. SARIF upload
is available for public repositories and for eligible private/internal
repositories with GitHub Code Security enabled.

SARIF artifact URIs are made relative to `GITHUB_WORKSPACE` when the target is
inside that workspace, and special path characters are URI-encoded. The
embedded `actions/setup-python` v6 runtime requires GitHub Actions Runner
2.327.1 or newer; GitHub-hosted runners already satisfy this requirement.

The Action is audit-only by default because some high-severity records are
privileged-capability inventory rather than proven defects. Set `fail-on`
explicitly only after reviewing a baseline and choosing a policy appropriate to
the target platform.

## Supported inputs

The static MVP scans local files only. It is intended for an unpacked
PostgreSQL extension source tree containing some or all of:

- primary and version-specific `*.control` files;
- generated control templates (`*.control.in`);
- matching install and upgrade `*.sql` / `*.sql.in` artifacts, including
  their version graph;
- C/C header source (`*.c`, `*.h`);
- Rust source (`*.rs`) and `Cargo.toml`.

It does not fetch a repository, download a release, unpack an untrusted archive,
connect to PostgreSQL, or resolve package dependencies. Scan an already checked
out, bounded directory. Directory scans fail closed when no supported source is
found, when a supported source is non-regular, or when the tree contains a
symlinked directory/source that could escape the reviewed boundary. It also
enforces limits on total entries, directories, path depth, path length, source
files, bytes, and findings.

See [Rule reference](docs/rules.md) for the implemented checks and input
coverage.

## What the MVP looks for

Rules are grouped around pre-admission questions:

- does control metadata declare privileged installation, sensitive
  requirements, or recursively included configuration?
- do install or upgrade scripts contain `COPY ... PROGRAM`, server-side file
  access, untrusted procedural languages, or public execution grants?
- are privileged functions missing defensive configuration such as a
  constrained `search_path`?
- does C or Rust source indicate filesystem, process, network, background
  worker, or unsafe-code capability that needs manual review?
- can the install/upgrade graph reach the declared default version, and can
  each artifact be associated with one unambiguous control-file scope?

PgExtAssure favors evidence and remediation over a single opaque score. A finding
can be a true security defect, a deliberate privileged capability, or a false
positive requiring suppression in a future release.

## Honest limitations

The static MVP:

- does not execute SQL or native code;
- does not prove the absence of malicious or vulnerable behavior;
- does not fully model PL/pgSQL, dynamic SQL, C/Rust semantics, PostgreSQL
  planner behavior, or runtime configuration;
- cannot establish that a scanned source tree matches a distributed binary;
- does not inspect transitive build dependencies or compiler behavior;
- does not validate install/upgrade equivalence;
- does not replace provenance verification, signature checking, sandboxed
  dynamic analysis, manual review, or production controls;
- may report false positives and false negatives.

To keep hostile inputs from creating unbounded reports, a file emits at most 32
findings per rule; the first retained finding records when additional matches
were omitted. A scan fails rather than returning a partial report if it exceeds
the global finding limit.

Do not use a clean PgExtAssure result as the sole reason to grant superuser,
filesystem, process, network, or preload privileges.

## How PgExtAssure fits with other tools

These tools solve different problems and can be used alongside PgExtAssure.

- [pgspot](https://github.com/timescale/pgspot) is the mature, AST-based
  specialist for PostgreSQL SQL and PL/pgSQL extension security. PgExtAssure's
  built-in SQL checks are a small offline baseline, not a claim to replace
  pgspot. A production assurance pipeline should ingest pgspot findings rather
  than duplicate its deeper SQL analysis.
- [pghostile](https://github.com/Aiven-Open/pghostile) creates adversarial
  database objects and exercises extension tests to expose privilege
  escalation. It is a valuable dynamic test and necessarily executes SQL in
  PostgreSQL. PgExtAssure's default scan remains non-executing and covers package
  metadata, native capability, update topology, evidence normalization, and CI
  policy.
- [CMU ExtAnalyzer](https://github.com/cmu-db/ext-analyzer) statically
  inventories extension API usage and dynamically measures installation and
  cross-extension compatibility. PgExtAssure is scoped to security-admission
  evidence rather than ecosystem compatibility research.
- [Splinter](https://github.com/supabase/splinter) runs SQL lints against a
  PostgreSQL/Supabase project's existing schema. PgExtAssure inspects an extension
  package before it is admitted or installed.
- [pgextwlist](https://github.com/dimitri/pgextwlist) enforces a runtime
  allowlist and can install approved extensions with elevated privileges.
  PgExtAssure supplies repeatable evidence for deciding what should enter that
  allowlist; it does not enforce installation policy.
- [pg_validate_extupgrade](https://github.com/rjuju/pg_validate_extupgrade)
  installs and upgrades an extension in PostgreSQL, then compares the resulting
  objects. It validates upgrade-path equivalence, not source security, and it
  necessarily executes the extension paths it tests.

## Threat model

PgExtAssure assumes the scanned tree may be malicious or compromised. The MVP
keeps that tree on the data side of the boundary: it reads recognized files and
does not invoke its build system, SQL, hooks, or binaries.

The principal protected assets are:

- PostgreSQL superuser and database-owner authority;
- database confidentiality, integrity, and availability;
- the PostgreSQL server process and host;
- the integrity of the extension admission decision and its evidence.

The main adversaries are a malicious extension author, a compromised upstream
release, and an otherwise benign maintainer who introduced an unsafe construct.
Runtime-only behavior, unknown parser evasions, transitive dependency attacks,
and source-to-binary substitution remain outside the static MVP's guarantees.

Read the complete [threat model](docs/threat-model.md) before using PgExtAssure as
a CI gate.

## Roadmap: isolated dynamic assurance

The next assurance layer is intentionally separate from the static scanner:

1. reproduce and attest the source-to-artifact build;
2. create an ephemeral, unprivileged PostgreSQL environment with no production
   credentials, default-deny network access, resource limits, and a disposable
   filesystem;
3. exercise install, upgrade, rollback, and representative calls;
4. capture catalog diffs, filesystem/process/network attempts, crashes, and
   other behavioral evidence;
5. destroy the environment and link the report to exact source and artifact
   digests.

Dynamic analysis will still be evidence, not certification. Details are in the
[roadmap](docs/roadmap.md).

## Public corpus loop

PgExtAssure is designed to create a useful public evidence corpus without making
source upload the default:

1. maintainers run the scanner locally or in CI;
2. they may opt in to publish a normalized report containing rule IDs,
   severities, scanner/rule-set versions, extension version, and cryptographic
   digests—not private source;
3. accepted fixes link a finding to a remediation diff;
4. the corpus improves regression fixtures, rule precision, and a versioned
   compatibility/admission badge;
5. better rules produce more useful local reports and more contributors.

No corpus upload or telemetry exists in the static MVP. Any future contribution
flow must be explicit opt-in, preview the exact payload, and support deletion.

## Privacy

- The scanner itself operates on local files and does not intentionally make
  network requests in the MVP.
- PgExtAssure does not intentionally send source, findings, or telemetry to a
  hosted service. CI setup and package-installation steps may download Python
  or build tooling independently of the scan.
- Reports can contain filenames, line numbers, and source excerpts. Treat them
  as potentially sensitive.
- `--output` writes only to the path you choose.
- Third-party CI systems, artifact upload steps, and SARIF services have their
  own data-handling policies; PgExtAssure cannot control them.

## Project documentation

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Changelog](CHANGELOG.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Rule reference](docs/rules.md)
- [Threat model](docs/threat-model.md)
- [Roadmap](docs/roadmap.md)
- [Public corpus pilot](benchmarks/public-corpus/README.md)

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

The CI workflow runs the same unit-test command.

## License

Apache License 2.0. See [LICENSE](LICENSE).
