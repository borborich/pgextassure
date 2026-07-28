# Rule reference

PgExtAssure's rules turn static source evidence into a prioritized review queue.
They are intentionally explainable: each finding should identify the rule,
severity, location, evidence, rationale, and a concrete review or remediation
step.

The implementation is the source of truth for exact rule identifiers and
matching behavior. This page describes the MVP coverage and its interpretation.

## Supported input classes

| Input | Coverage goal | Important boundary |
| --- | --- | --- |
| `*.control`, `*.control.in` | Privileged-install metadata and declared default version | Metadata can describe risk but cannot prove implementation safety |
| matching `*.sql`, `*.sql.in` | Install and version-to-version upgrade scripts | Static matching does not fully model SQL or PL procedural-language semantics |
| `*.c`, `*.h` | Recognized filesystem, process, network, and background-worker indicators | Presence is evidence for review, not proof of a defect |
| `*.rs` | Recognized unsafe, filesystem, process, and network indicators | Presence is evidence for review, not proof of a defect |
| `Cargo.toml` | Direct runtime/build dependencies with selected host-capability categories | A dependency name does not prove that its capability is used or reachable |

Unknown files are not proof of unsupported behavior being absent. Reports should
be interpreted together with the scanned-file inventory.

## Rule families

### Control metadata

The MVP flags control metadata that declares privileged installation and reads
the declared default version for upgrade-graph analysis. Recursive
`include`, `include_if_exists`, and `include_dir` directives fail closed because
their effective settings are outside the scanned control document.
Version-specific `extension--version.control` files inherit their matching
primary control before explicit overrides are assessed, including conventional
source layouts that place scripts in the primary control's configured
`directory`.

Review questions include:

- Does a superuser requirement accurately reflect the extension's behavior?
- Which roles will be able to request installation in the target platform?
- Has the complete install and upgrade path received equivalent review?

### Privileged SQL

The MVP checks for:

- `COPY ... PROGRAM`;
- server-side file access through `COPY`;
- untrusted PL/Python and PL/Perl declarations;
- function execution granted to `PUBLIC`;
- `SECURITY DEFINER` functions without a recognized constrained
  `search_path`, including `ALTER ... SECURITY DEFINER`;
- newly created `SECURITY DEFINER` routines without a later, recognizable
  `REVOKE ... FROM PUBLIC`;
- later `ALTER` statements that reset or make the `search_path` unsafe for a
  routine previously marked `SECURITY DEFINER`;
- an unsafe or indeterminate routine `search_path` mutation when the routine's
  privilege state is not present in the scanned script
  (`sql.routine-unsafe-search-path`).

Static evidence does not determine whether a construct is reachable or
exploitable. Review the full statement and the privileges under which it runs.

### Name resolution and `search_path`

PostgreSQL extension scripts and privileged functions can be exposed to
search-path attacks. The built-in MVP check looks for `SECURITY DEFINER`
routines without a recognized constrained path. It does not perform full name
resolution or comprehensively detect unsafe unqualified references; use a
PostgreSQL AST specialist such as pgspot for that analysis.

Mitigation normally includes:

- a safe `search_path`, commonly constrained to trusted schemas such as
  `pg_catalog` and `pg_temp` as appropriate;
- explicit schema qualification;
- exact argument casts where overload resolution matters;
- review against the current PostgreSQL extension-security documentation.

No regular expression can prove complete name-resolution safety.

### Native and host capability

A native extension executes within the PostgreSQL server process. C checks
inventory indicators of:

- filesystem access;
- subprocess or shell execution;
- outbound networking;
- background-worker registration.

Rust checks inventory recognized:

- `unsafe` blocks;
- filesystem access;
- process execution;
- network access.

These capabilities may be legitimate. They raise the required review and
isolation level because a defect or malicious path can affect the database host,
not merely one SQL schema.

### Upgrade graph

The scanner derives versions and directed upgrade edges from conventional
extension SQL filenames. It flags a graph in which an installable version
cannot reach the control file's declared `default_version`. It also emits
`update.ambiguous-scope` when duplicate controls prevent a safe association
between an SQL artifact and exactly one package scope.

This is a structural check only. PgExtAssure does not execute an upgrade, compare
catalog objects, or prove that the SQL on a connected path is correct.

When reviewed build metadata generates a missing install SQL or final control
file, an explicit [generation plan](generation-plans.md) can add a pinned
virtual artifact to this analysis. Declared SQL affects only graph structure;
rendered templates are scanned at their generated path. No build command is
executed.

## Severity interpretation

| Severity | Intended interpretation |
| --- | --- |
| `critical` | Evidence of a direct, high-impact path that should block admission pending expert review |
| `high` | Privileged or host-impacting behavior, or a strong unsafe pattern |
| `medium` | Material hardening gap or capability requiring explicit review |
| `low` | Inventory, hygiene, or defense-in-depth signal |

Severity is a default estimate, not a universal risk rating. Deployment context
may change likelihood and impact.

## False positives and false negatives

Expected false positives include deliberately privileged extensions, defensive
code containing suspicious API names, generated fixtures, and safe constructs
the static matcher cannot fully understand. In this alpha, named routine
arguments and schema-wide/default-privilege revocations may not be correlated
with a later exact `REVOKE`, so manual review may clear an otherwise
conservative PUBLIC-execution finding.

Expected false negatives include dynamic SQL, macros, indirect calls,
obfuscation, unsupported languages, generated source absent from the tree, and
behavior located in dependencies or binaries.

Each source file retains at most 32 findings for one rule. When more matches
exist, the first retained finding records the total observed count. The scan
fails instead of emitting a partial report if the global finding limit is
exceeded.

The MVP should prefer a cited finding over an unexplained aggregate score.
Suppressions are not documented until the CLI implements a reviewable,
versioned suppression mechanism.

## Root-cause grouping

`--format grouped-json` produces a review-oriented report alongside the stable
JSON v1 and SARIF formats. The grouping strategy is deliberately conservative:

- matching `sql.security-definer-search-path` records are grouped only when
  their parsed routine identity and extension artifact scope match;
- matching `sql.security-definer-public-execute` records use the same rule;
- all other findings remain scoped to their original source location.

Every group retains all source locations and reports its occurrence count. A
stable `root_cause_id` is derived from the rule, severity, capability, artifact
scope, and semantic identity; it does not depend on line numbers for supported
semantic groups. Moving the same routine between versioned upgrade scripts
therefore does not create a new review item, while identically named routines
in separate extension package scopes are not merged.

Grouping reduces duplicated review work. It does not reduce the raw finding
count, change `--fail-on`, suppress a finding, or establish exploitability.

## Rule evolution

A report should be associated with a PgExtAssure version and rule-set version.
Changes to rules can change findings even when extension source is unchanged.
Admission records should therefore pin:

- extension source revision or digest;
- PgExtAssure revision/version;
- report format/schema version;
- gate threshold;
- reviewed exceptions.

Re-run the scan when any of those inputs changes.
