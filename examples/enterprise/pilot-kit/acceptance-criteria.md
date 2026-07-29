# Pilot acceptance criteria

Record one result for every criterion. A failed security criterion blocks pilot
acceptance; an explicitly out-of-scope criterion must include an owner and
reason.

| ID | Criterion | Required result |
| --- | --- | --- |
| AC-01 | Target code execution | No target build, import, SQL execution, or shared-library load |
| AC-02 | Network dependency | Offline bundle and signature verification succeed |
| AC-03 | Evidence integrity | Exact bundle, manifest, coverage, and policy digests verify |
| AC-04 | Signature integrity | RSA-PSS-SHA256 signature validates with RSA >=3072 |
| AC-05 | Signer trust | Reported key fingerprint matches an independently delivered fingerprint |
| AC-06 | Tamper rejection | One-byte mutation causes a non-zero verification result |
| AC-07 | Policy outcome | `pass`/`blocked` is visible and recomputed from retained evidence |
| AC-08 | Coverage | Skipped-file count satisfies the reviewed organization policy |
| AC-09 | Source confidentiality | Evidence archive contains no source-file payloads |
| AC-10 | Decision boundary | Valid evidence is not treated as automatic installation authority |
| AC-11 | Reproducibility | Same source and control inputs produce the same unsigned evidence bytes |
| AC-12 | Key handling | Private key and passphrase are absent from delivered artifacts and logs |
| AC-13 | Trust anchor | Exact trust-policy digest is obtained independently |
| AC-14 | Key revocation | A revoked trusted key produces a deny receipt |
| AC-15 | Evidence age | Stale or future evidence/signatures produce deny receipts |
| AC-16 | Policy binding | A non-allowlisted evidence policy digest is denied |
| AC-17 | Request context | Modified request ID, target, or evaluation date fails verification |
| AC-18 | Receipt lifetime | Expired receipts remain verifiable but are not active |
| AC-19 | Handoff integrity | Outer pilot package and every manifest-bound payload verify before extraction |
| AC-20 | Release provenance | Included distributions match release checksums and independently trusted provenance |

Suggested retained record:

```text
Pilot:
Extension source revision/digest:
PgExtAssure release commit:
Evidence bundle SHA-256:
Corporate signer ID:
Trusted public-key SHA-256:
Enterprise trust-policy SHA-256:
Request ID and target:
Verification date:
Verifier:
Gate:
Admission Receipt decision and valid-until:
Pilot package SHA-256:
Distribution provenance verification:
Criteria passed:
Exceptions, owner, expiry:
Final pilot disposition:
```
