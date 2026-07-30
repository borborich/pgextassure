# Enterprise pilot

The pilot kit demonstrates a strict, reviewable PostgreSQL-extension admission
gate. Copy [`examples/enterprise/`](../examples/enterprise/) into a pilot
repository, then replace `REPLACE_WITH_RELEASE_COMMIT` with the immutable commit
SHA of a PgExtAssure release that contains Evidence Bundle 1.0.

The example assumes:

- extension sources are under `extension/`;
- policy is outside that scan root;
- evidence is written outside the scan root;
- the repository permits GitHub OIDC artifact attestations;
- the workflow is a required pull-request check.

The sample policy blocks high and critical findings plus filesystem,
unsafe-memory, network, background-worker, and process-execution capabilities.
It permits no skipped files, baselines, or suppressions. This is a starting
point, not a universal organization policy.

Before a pilot:

1. review each policy selector with database platform and security owners;
2. choose a supported-source scan root narrow enough for
   `maximum_skipped_files: 0`;
3. pin PgExtAssure to an immutable release commit, not a branch or floating tag;
4. set artifact retention and repository access to match report sensitivity;
5. make the final `Enforce admission result` step a required check;
6. verify one downloaded bundle locally and with `gh attestation verify`;
7. document exception ownership before enabling suppressions.

The Action creates the bundle even for a blocked decision. Its workflow step is
allowed to continue so the evidence and attestations are retained, then a final
step restores the blocking outcome.

GitHub artifact attestations link an artifact to the repository, commit,
workflow and OIDC-backed signer. They establish provenance and integrity, not
security certification. Public repositories use the public Sigstore service;
private/internal availability depends on the GitHub plan.

For organizations that cannot use GitHub OIDC or an external transparency
service, Corporate Evidence Signature Profile 1.0 provides detached offline
RSA-PSS-SHA256 signing and verification. The transferable evaluation package
is under [`examples/enterprise/pilot-kit/`](../examples/enterprise/pilot-kit/).
It includes a thirty-minute acceptance path, explicit criteria, independent
verification steps, and concise security-questionnaire answers.

The kit also includes an Enterprise Trust Policy template and Admission
Receipt workflow. This layer demonstrates key rotation/revocation, exact
tool/ruleset/policy constraints, evidence freshness, request-context binding,
and the difference between a cryptographically valid artifact and an active
organization admission decision.

Enterprise Pilot Package 1.0 closes the handoff layer around those artifacts.
It creates a deterministic, manifest-bound, non-extracting-verifiable ZIP with
the exact release distributions and retained verification results while
rejecting unrecognized payloads and common private-key formats. See
[Enterprise Pilot Package 1.0](pilot-packages.md).

The next integration boundary is the one-shot
[`pilot enforce`](enterprise-integrations.md) command and dedicated GitHub
sub-action. They bind the complete package to out-of-band trust anchors,
recompute its signature and receipt, and emit Admission Event 1.0 for CI,
Jira, ServiceNow, or SIEM ingestion.

For a no-meeting customer handoff, use the
[self-service pilot acceptance runner](pilot-acceptance.md). One command
verifies the package offline, proves the deployed TLS 1.3/mTLS boundary,
performs the first admission, verifies byte-identical replay, and writes a
closed canonical report for the receiving security team.
