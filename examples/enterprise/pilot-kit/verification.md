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
