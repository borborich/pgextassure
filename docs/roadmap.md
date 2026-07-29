# Roadmap

PgExtAssure starts with a deliberately non-executing static boundary. Later
assurance layers should add evidence without weakening that default.

## MVP: static pre-admission scan

- local directory and file inputs;
- control, SQL, native-source, and build-metadata rules;
- text, JSON, and SARIF reports;
- severity-based CI gate;
- no target build, install, import, SQL execution, or telemetry.

## Next: precision and review workflow

- documented versioned report and input schemas;
- bounded parsing and explicit skipped-file inventory;
- source/release digests and reproducible report metadata;
- remediation tests built from accepted upstream fixes;
- optional GitHub annotations and additional policy templates.

Implemented in the current alpha: conservative root-cause grouping,
ruleset-bound baselines, exact expiring owner-attributed suppressions, a strict
organization-owned policy gate, versioned JSON schemas, and explicit bounded
coverage inventory. Alpha 4 also provides bounded, evidence-free GitHub
annotations and packaged adoption/strict policy templates. All report evidence
is retained.

Alpha 5 adds deterministic Evidence Bundle 1.0, non-extracting offline
verification, a bounded SPDX analyzed-source inventory, and a
keyless-attestation enterprise pilot workflow. The SPDX inventory does not
claim transitive dependency resolution.

The current development line adds Agent Review Pack 1.0: a deterministic,
digest-bound task queue for assisted review. It explicitly denies admission
authority to the agent; a separately validated decision ledger remains next.

## Isolated dynamic assurance

Dynamic analysis must be a separate opt-in command and execution service. A
planned run would:

1. accept a pinned source tree and record its digest;
2. build in a disposable builder with dependency and network policy;
3. transfer only the resulting artifacts and manifest into a separate runner;
4. start an ephemeral unprivileged PostgreSQL cluster;
5. exercise clean install, supported upgrade paths, rollback/failure behavior,
   and representative calls;
6. collect database-catalog diffs, logs, crashes, resource use, and attempted
   filesystem, process, and network operations;
7. destroy both environments;
8. emit a signed evidence bundle linked to source, artifact, PostgreSQL image,
   scenario, and rule-set digests.

Minimum isolation requirements:

- never use production data, credentials, hosts, or networks;
- default-deny egress;
- read-only base filesystem plus bounded disposable storage;
- unprivileged database and operating-system identities;
- CPU, memory, disk, process, and wall-clock limits;
- syscall and filesystem policy appropriate to the runner;
- stronger isolation than a shared container for hostile native code;
- auditable cleanup and report redaction.

Dynamic evidence will not certify safety. It observes exercised paths under one
environment and can miss dormant, conditional, or evasive behavior.

## Public corpus

A future corpus contribution flow may accept normalized, explicitly previewed
records:

- extension name/version and source digest, when public;
- rule ID, severity, tool/rule-set version;
- minimal redacted evidence fingerprint;
- disposition: fixed, accepted, false positive, or unresolved;
- linked public remediation commit when available.

Private source and full reports must never be uploaded implicitly. Contribution
must be opt-in and revocable.

Useful corpus outputs could include:

- precision/regression fixtures;
- common remediation patterns;
- versioned extension assurance badges;
- ecosystem-level trends without ranking an extension as universally “safe”.

## Explicitly not on the roadmap

- a universal “certified safe” label;
- automatic production installation;
- opaque AI-only verdicts without cited evidence;
- default source upload;
- silently converting a clean scan into an allowlist grant.
