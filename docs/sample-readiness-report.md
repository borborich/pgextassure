# Illustrative Extension Admission Readiness Report

**Status:** Example structure only  
**Subject:** Controlled demonstration extension  
**Decision owner:** Example Platform Security Team  
**PgExtAssure release:** `0.1.0-alpha.16`

This document shows the shape of a Founding Partner Evaluation deliverable. It
is not based on a customer engagement and is not a security assessment,
certification, endorsement, or permission to install an extension.

## 1. Decision summary

| Field | Illustrative result |
| --- | --- |
| Requested decision | Whether the pinned source is ready to enter manual admission review |
| Automated gate | `review required` |
| Final admission decision | Not made by PgExtAssure |
| Evidence integrity | Independently verifiable |
| Source execution | None performed by the static workflow |
| Remaining work | Manual review and organization-specific runtime/provenance checks |

The automated result identifies and organizes review work. A pass would mean
only that the supplied policy did not block the recorded evidence; it would not
prove the extension safe.

## 2. Bound inputs

The real report records exact values for:

- source repository, revision, and acquisition method;
- analyzed-source manifest SHA-256;
- PgExtAssure release and ruleset versions;
- organization-policy SHA-256;
- generation or scope plans, when used;
- evidence bundle SHA-256;
- skipped-file inventory and declared coverage limits.

Private source-file payloads are not embedded in Evidence Bundle 1.0. Reports
may contain paths, line numbers, and short matched excerpts and must still be
handled as security-sensitive artifacts.

## 3. Review queue

| Root cause | Classification | Required owner action |
| --- | --- | --- |
| Privileged install/upgrade behavior | Capability requiring review | Confirm necessity and least-privilege boundary |
| `SECURITY DEFINER` routine | Potential authority boundary | Verify constrained `search_path`, qualification, grants, and caller model |
| Native filesystem/process/network indicator | Capability inventory | Trace reachable behavior and apply platform policy |
| Unsupported or generated input | Coverage limitation | Supply a pinned generation/scope plan or retain as unresolved |

The real queue contains exact source citations and a closed disposition
vocabulary. Similar locations are grouped only when PgExtAssure can establish a
shared routine identity.

## 4. Policy and evidence result

The receiving organization supplies or approves the policy. The evaluation
records:

- minimum blocking severity;
- blocked capability classes and exact rules;
- maximum skipped-file count;
- whether baselines or expiring suppressions are permitted;
- every exception's owner, reason, ticket, and expiry;
- the recomputed gate result.

A cryptographically valid bundle with a `blocked` gate remains a valid record
of a denial. Signature validity is not installation authority.

## 5. Acceptance record

The evaluation is complete when the receiving engineer has:

1. verified the exact evidence bundle;
2. reproduced the intended gate from pinned inputs;
3. confirmed that a one-byte mutation is rejected;
4. inspected coverage and unresolved review items;
5. retained the result with the organization's decision record;
6. recorded the organization-owned final disposition.

## 6. Limitations retained in every report

PgExtAssure does not execute SQL or native code, prove absence of malicious or
vulnerable behavior, establish source-to-binary equivalence, inspect all
transitive build dependencies, or replace manual review, provenance checks,
isolated runtime testing, and production controls.

## 7. Possible next decisions

- **Stop:** the workflow does not reduce review ambiguity or fit the intake
  boundary.
- **Revise:** adjust inputs or policy, then repeat the bounded evaluation.
- **Pilot:** integrate the evidence workflow into one real admission queue.
- **Adopt with limits:** retain the static gate as one input to a broader
  organization-owned assurance process.

