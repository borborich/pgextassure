# PgExtAssure threat model

Status: static MVP

This document describes what PgExtAssure is designed to protect, what it trusts,
and what conclusions a reviewer may and may not draw from a report.

## Security objective

PgExtAssure helps a platform or database team identify security-relevant evidence
in a PostgreSQL extension source package **before** the package is allowlisted,
built, installed, or upgraded in a database environment.

The objective is risk reduction and review consistency. The objective is not to
certify an extension, prove non-maliciousness, or replace human approval.

## Assets

The admission process should protect:

1. PostgreSQL superuser, database-owner, and extension-owner authority.
2. Confidentiality and integrity of database contents.
3. Availability of the database and surrounding services.
4. The PostgreSQL server process, host filesystem, process namespace, and
   network identity.
5. Credentials and secrets reachable from the database host or CI runner.
6. Integrity and reproducibility of the extension admission decision.
7. Confidentiality of the source package and the generated report.

## Actors and adversaries

PgExtAssure considers:

- a malicious extension author who expects install or runtime code to receive
  elevated privileges;
- an attacker who compromised an upstream maintainer, source repository,
  release artifact, or dependency;
- a maintainer who accidentally introduced an unsafe control setting, SQL
  construct, native capability, or upgrade path;
- a reviewer or CI configuration that applies an inappropriate severity
  threshold;
- an attacker crafting input to confuse, evade, exhaust, or exploit the static
  scanner.

The CI runner, Python interpreter, PgExtAssure package, and checked-out PgExtAssure
revision are trusted in the MVP. A compromised scanner or runner is outside the
tool's ability to detect.

## Trust boundaries

```text
untrusted extension tree
          |
          | read recognized files; never invoke target code
          v
 PgExtAssure static scanner  ----> local text/JSON/SARIF report
          |                              |
          |                              | optional explicit upload
          v                              v
   exit-code CI gate              reviewer / GitHub service
          |
          v
 separate human admission decision
```

The key MVP boundary is between untrusted extension content and executable
behavior. PgExtAssure must treat the target as data. It must not:

- source shell files;
- invoke Make, Cargo, a compiler, package hooks, or target-provided scripts;
- execute SQL in PostgreSQL;
- import Python or other modules from the target;
- load a target shared library;
- follow a target-controlled instruction to access the network.

An optional generation plan remains on the data side of this boundary. It can
declare pinned virtual SQL paths or literal substitutions over a pinned
template, but cannot invoke a command, Make target, shell expansion, compiler,
or script. The plan is a reviewer assertion and must not be trusted merely
because it came from the target repository. Reports bind its exact digest and
verified input digests to the scan.

Installing PgExtAssure itself is distinct from scanning the target. In the
composite GitHub Action, the package installed from `GITHUB_ACTION_PATH` is the
selected PgExtAssure action revision, not the target extension.

## Threats the static MVP can surface

Subject to the implemented rules and parser coverage, reports may surface:

- control metadata that changes installation privilege or trust assumptions;
- privileged or security-sensitive SQL constructs in install and upgrade
  scripts;
- unsafe or missing defensive configuration around privileged functions;
- indicators of native code and server-process integration that require deeper
  review;
- indicators of filesystem, process, network, preload, hook, or similar
  capabilities;
- risky combinations, such as broad installability plus privileged behavior.

A finding means that a reviewer should investigate the cited evidence. It does
not necessarily mean the extension is exploitable.

## Threats not resolved by a clean report

A clean static scan cannot rule out:

- malicious behavior hidden behind dynamic SQL, macros, generated code,
  obfuscation, unusual encodings, or parser gaps;
- memory-safety, concurrency, undefined-behavior, or logic defects in native
  code;
- behavior activated only by a particular PostgreSQL version, configuration,
  locale, architecture, input, timing condition, or dependency;
- malicious compilers, build plugins, package registries, or transitive
  dependencies;
- a binary or archive that does not correspond to the scanned source;
- vulnerabilities in PostgreSQL itself;
- unsafe operational configuration or excessive privileges granted after
  admission;
- availability failures caused by expensive but syntactically ordinary work;
- data exfiltration through a capability that static rules did not recognize.

PgExtAssure also does not determine licensing, export-control, privacy,
regulatory, or contractual compliance.

## Input attacks against the scanner

The source tree is untrusted input. Implementations and deployments should
defend against:

- very large files or directory trees intended to exhaust memory, CPU, disk, or
  log storage;
- symlinks and path traversal that escape the requested scan root;
- binary files disguised with supported suffixes;
- malformed control files, SQL, source, or encodings;
- deeply nested or adversarial syntax;
- terminal-control characters or report injection;
- secrets embedded in evidence snippets.

The MVP's static architecture limits consequences, but does not make the parser
immune to denial of service or implementation bugs. Run scans with normal CI
resource limits and review generated reports before publishing them.

Current fail-closed guards reject symlinked scan roots, symlinked directories
and supported source files, non-regular sources, binary/non-UTF-8 inputs,
unsupported empty trees, oversized inputs, excessive directory entries/depth,
and reports above the finding cap. Report files are replaced atomically;
final-component output symlinks and symlinked output directories below the
workspace boundary are rejected. The GitHub Action runs Python in isolated mode
so caller-workspace modules and `sitecustomize.py` cannot shadow its installed
scanner. These controls reduce exposure but are not a complete sandbox.

Generation plans additionally reject duplicate/unknown fields, path traversal,
symlinks, non-regular or stale pinned inputs, target collisions, unsafe literal
substitutions, and excessive plan/input/rendered-output sizes and counts.

## Admission guidance

Use PgExtAssure as one input in a layered decision:

1. Pin and verify the upstream source revision.
2. Run PgExtAssure with a documented severity policy.
3. Resolve or explicitly review every finding.
4. Perform manual review proportional to extension capabilities.
5. Reproduce the build and verify artifact provenance where possible.
6. Test install and upgrade behavior only in an isolated disposable
   environment.
7. Restrict runtime roles, schemas, filesystem, network, preload settings, and
   host privileges.
8. Re-scan every source, dependency, rule-set, PostgreSQL, or extension-version
   change.

An allowlist entry should identify the exact extension version or digest and
the report/rule-set version used for the decision. Do not treat an extension
name as a permanent grant.

## Severity and gate limitations

Severity estimates impact under common deployment assumptions. Local context
can raise or lower actual risk. For example, native code is inherently
high-impact inside the server process, but the mere presence of native code is
not proof of a vulnerability.

`--fail-on` is an automation convenience. It does not turn a heuristic finding
into a policy decision. Teams should document:

- the selected threshold;
- exceptions and their owners;
- accepted versions or digests;
- required manual review;
- conditions that trigger re-review.

## Future dynamic-analysis boundary

Dynamic analysis will deliberately cross the non-execution boundary, so it must
run as a separate subsystem:

- never on a developer's normal database or a production host;
- build and execution separated into disposable isolation domains;
- unprivileged PostgreSQL user;
- no real credentials or customer data;
- default-deny egress and explicit syscall/filesystem controls;
- strict CPU, memory, disk, process, and time limits;
- captured source and artifact digests;
- complete destruction after each run.

Even a sandbox escape must be included in that system's threat model. Containers
alone should not be presented as a complete trust boundary for hostile native
extensions.

## Non-claims

PgExtAssure does not claim:

- certification or formal verification;
- complete vulnerability detection;
- fitness for a particular regulated environment;
- legal or compliance assurance;
- that a report is sufficient authorization to install an extension.

Report wording and downstream integrations should preserve these non-claims.
