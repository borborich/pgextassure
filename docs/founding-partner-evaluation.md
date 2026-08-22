# Founding Partner Evaluation

PgExtAssure is offering a bounded, mostly asynchronous evaluation for teams that
review PostgreSQL extensions before allowlisting, building, or installing them.

This is engineering evidence for an organization-owned decision. It is not a
penetration test, security certificate, compliance conclusion, or authorization
to install an extension.

## Intended participants

- PostgreSQL consultancies and security assessment firms;
- managed PostgreSQL platform teams;
- commercial extension teams preparing an admission package for downstream
  platforms;
- internal database platform or product-security teams with an existing
  extension intake decision.

The evaluation is not a fit when there is no named admission decision, no
approved source snapshot, or an expectation that a static tool will certify an
extension as safe.

## Fixed founding scope

- ten business days after approved inputs are available;
- one extension source snapshot or one small agreed extension family;
- one organization-owned policy profile;
- one customer-controlled CI or isolated-runner path;
- deterministic reports and one verified Evidence Bundle 1.0;
- one reviewer handoff and one written limitations register;
- enablement material for one receiving engineer;
- one independent rerun by the receiving team.

No PgExtAssure-hosted service is required. Source and findings remain in the
participant's environment unless the participant explicitly approves a
different exchange.

## Deliverables

1. Pinned input and provenance manifest.
2. Versioned admission policy.
3. Machine-readable findings and grouped review queue.
4. Verified evidence bundle and limited SPDX 2.3 inventory.
5. CI configuration or documented customer-controlled command path.
6. Acceptance record, limitations, unresolved review items, and recommended
   next decision.

See the [illustrative readiness report](sample-readiness-report.md) for the
shape of the final handoff. It contains no customer result or certification.

## Acceptance conditions

- inputs are bound to exact revisions or digests;
- the receiving team can regenerate or independently verify the artifacts;
- a deliberate one-byte mutation fails verification;
- the organization policy produces the expected result for an agreed positive
  or negative control;
- unresolved limitations and manual-review work are retained rather than
  silently suppressed;
- final admission authority remains with the participant.

## Founding commercial terms

The planning price for the fixed scope is **EUR 15,000**, excluding applicable
taxes and pre-approved pass-through expenses. The fee may be credited against a
follow-on focused pilot when that credit is included in the signed statement of
work.

Final scope, availability, confidentiality, IP, liability, payment, privacy,
and acceptance terms require a written agreement. This page is not a binding
quote.

## Start asynchronously

No introductory meeting is required.

- For a public open-source repository, open a
  [public evaluation request](https://github.com/borborich/pgextassure/issues/new?template=evaluation-request.yml).
- For private source or a non-public workflow, email
  [boris@shbb.pro](mailto:boris@shbb.pro?subject=PgExtAssure%20Founding%20Partner%20Evaluation&body=Organization%3A%0ARole%3A%0APublic%20or%20private%20extension%3A%0ACurrent%20admission%20decision%3A%0AApproved%20execution%20boundary%3A%0ADesired%20decision%20date%3A%0A).

Include only:

1. organization and role;
2. public repository URL, or state that the source is private;
3. the admission decision the evidence must support;
4. the approved execution boundary;
5. the desired decision date.

Do not send private source, credentials, vulnerability details, or sensitive
findings in the first message. Security reports must follow
[`SECURITY.md`](../SECURITY.md).

