# Independent external reproduction

PgExtAssure's external reproduction protocol lets an independent operator
reproduce one deterministic scanner artifact and two PostgreSQL authority-
boundary semantics without installing or executing third-party extension code.
It is designed for public forks and takes approximately 15 minutes of unattended
GitHub Actions time.

The protocol is evidence of reproducibility, not a security certification,
benchmark ranking, endorsement, or extension allowlist decision.

## What the workflow checks

The workflow:

1. checks out PgExtAssure `0.1.0-alpha.16` at immutable commit
   `96e0f14fe8f2f86a11be1341f87ddece9385a8b2`;
2. scans a disclosure-safe controlled fixture without building, installing,
   loading, importing, or executing it;
3. verifies the complete Evidence Bundle and requires the canonical SHA-256
   `e4a7b2e46591ca0519345664a77c203bcced7532cf2733dbe372376e10c53790`;
4. starts the digest-pinned PostgreSQL 16.13 container already used by project
   CI;
5. demonstrates that an unsafe `SECURITY DEFINER` lookup can resolve a caller-
   controlled function and operator while a constrained `search_path` prevents
   that lookup;
6. demonstrates that a role with effective `PUBLIC EXECUTE` can attach a
   regular `SECURITY DEFINER` trigger function to a table it owns and invoke it
   with the function owner's authority;
7. writes a closed JSON report and SHA-256 inventory;
8. uploads the result for 90 days and attempts GitHub artifact attestations.

Only controlled project fixtures and SQL are executed. No public extension
corpus repository is cloned or executed, and no private source is requested.

## Run in a fork

1. Sign in to GitHub and open
   <https://github.com/borborich/pgextassure>.
2. Select **Fork**, keep the default repository name, and create the fork.
3. In the fork, open **Actions** and enable workflows if GitHub asks.
4. Select **Independent external reproduction**.
5. Select **Run workflow**, leave the branch unchanged, and confirm.
6. Wait for the job **Reproduce alpha.16 evidence and PostgreSQL semantics**.
7. Open the completed run and download the
   `pgextassure-external-reproduction` artifact.
8. Verify that `external-reproduction-report.json` contains
   `"outcome": "pass"` and that `sha256sum --check SHA256SUMS` succeeds.
9. Submit the run through the
   [External reproduction report](https://github.com/borborich/pgextassure/issues/new?template=external-reproduction.yml)
   form.

Do not rerun a failing job until the original failure and any workflow changes
have been recorded. A failed result is useful and should be submitted.

## Independence criteria

The project may count a result as an independent external reproduction only
after confirming that:

- the operator is not the project author and used an account or organization
  they control;
- the run used an unmodified protocol revision from the canonical repository;
- the immutable PgExtAssure implementation commit and digest-pinned PostgreSQL
  image are visible in the workflow;
- the uploaded result and its checksums match the workflow log;
- compensation, if any, was fixed for completing the protocol and not contingent
  on the outcome;
- relevant professional, financial, or organizational relationships were
  disclosed.

Two runs by different people in two independently controlled forks may satisfy
the technical reproduction gate. They do not establish commercial demand. A
separate design-partner pilot must exercise an organization's actual extension
admission workflow and policy.

## Data handling

The uploaded bundle contains evidence excerpts from the controlled fixture.
The fixture is intentionally public and contains no third-party findings. Do
not replace its path with a private repository or upload a private scan into a
public fork.

GitHub artifact attestations can be unavailable because of fork or account-plan
constraints. That does not silently convert a failed verification into a pass:
the deterministic artifact digest, workflow log, report, and `SHA256SUMS`
remain mandatory, while attestation availability is recorded separately in the
workflow summary.

For Russian-language operator instructions, see
[`external-reproduction.ru.md`](external-reproduction.ru.md).
