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

Suggested retained record:

```text
Pilot:
Extension source revision/digest:
PgExtAssure release commit:
Evidence bundle SHA-256:
Corporate signer ID:
Trusted public-key SHA-256:
Verification date:
Verifier:
Gate:
Criteria passed:
Exceptions, owner, expiry:
Final pilot disposition:
```
