# Independent verification

Prerequisites:

- Python 3.11 or later;
- a pinned PgExtAssure distribution;
- OpenSSL 3.x or a compatible OpenSSL executable;
- the four delivered artifacts in the current directory;
- the trusted public-key fingerprint obtained separately.

No network connection is required by these commands.

```bash
python -m pgextassure evidence verify pgextassure-evidence.zip \
  --format json

python -m pgextassure evidence verify-signature \
  pgextassure-evidence.zip \
  --statement pgextassure-signature.json \
  --signature pgextassure-signature.bin \
  --public-key pgextassure-public-key.pem \
  --expected-key-sha256 'sha256:TRUSTED_64_HEX_DIGEST' \
  --format json
```

Retain the JSON output with the receiving organization's ticket or approval
record. Verification is successful only when the command exits `0`,
`"valid": true` is present, the fingerprint equals the independently trusted
fingerprint, and the gate has the value expected by the receiving policy.

`"gate": "blocked"` can be correctly signed and cryptographically valid. It is
evidence that the policy blocked the subject, not permission to install it.

For a negative control, make a copy of one delivered artifact, alter it, and
confirm the corresponding verifier exits `3`. Never alter the retained
originals.

After replacing the placeholder signer in `../trust-policy.json`, create and
independently recompute an Admission Receipt:

```bash
python -m pgextassure trust evaluate pgextassure-evidence.zip \
  --statement pgextassure-signature.json \
  --signature pgextassure-signature.bin \
  --public-key pgextassure-public-key.pem \
  --trust-policy ../trust-policy.json \
  --evaluated-on 2026-07-29 \
  --request-id PILOT-2026-0042 \
  --target pilot/postgresql-extension \
  --output pgextassure-admission-receipt.json

python -m pgextassure trust verify-receipt \
  pgextassure-admission-receipt.json \
  --bundle pgextassure-evidence.zip \
  --statement pgextassure-signature.json \
  --signature pgextassure-signature.bin \
  --public-key pgextassure-public-key.pem \
  --trust-policy ../trust-policy.json \
  --expected-trust-policy-sha256 \
  'sha256:TRUSTED_64_HEX_DIGEST' \
  --expected-request-id PILOT-2026-0042 \
  --expected-target pilot/postgresql-extension \
  --expected-evaluated-on 2026-07-29 \
  --verified-on 2026-07-29
```

The ticket or deployment system must enforce request-ID uniqueness. PgExtAssure
binds and verifies the context but does not maintain a shared replay database.
