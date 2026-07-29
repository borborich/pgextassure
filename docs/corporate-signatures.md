# Corporate Evidence Signature Profile 1.0

Corporate Evidence Signature Profile 1.0 lets an organization sign and verify
a PgExtAssure Evidence Bundle without GitHub, OIDC, Sigstore, a network
connection, or a PgExtAssure service account. The detached artifacts can move
through an existing document, ticket, artifact, or release-approval system.

This profile uses:

- RSA-PSS with SHA-256 and a minimum RSA modulus of 3072 bits;
- an X.509 SubjectPublicKeyInfo PEM public key;
- a canonical JSON statement described by
  [`evidence-signature-1.0.schema.json`](../schemas/evidence-signature-1.0.schema.json);
- an external binary signature, so signing does not alter the evidence ZIP;
- a caller-selected signer ID whose meaning is owned by the organization.

OpenSSL is required only for `evidence sign` and `evidence verify-signature`.
The scanner and Evidence Bundle creator retain PgExtAssure's dependency-free,
non-executing boundary.

## Sign

Use a reviewed Evidence Bundle and an organization-controlled private key:

```bash
pgextassure evidence sign pgextassure-evidence.zip \
  --private-key corporate-release-key.pem \
  --signer-id acme-security/postgresql-admission-key-01 \
  --created-on 2026-07-29 \
  --statement-output pgextassure-signature.json \
  --signature-output pgextassure-signature.bin \
  --public-key-output pgextassure-public-key.pem
```

For an encrypted PEM key, place the passphrase in an environment variable and
name that variable without putting the secret on the command line:

```bash
pgextassure evidence sign pgextassure-evidence.zip \
  --private-key corporate-release-key.pem \
  --passphrase-env PGEXTASSURE_SIGNING_PASSPHRASE \
  --signer-id acme-security/postgresql-admission-key-01 \
  --statement-output pgextassure-signature.json \
  --signature-output pgextassure-signature.bin \
  --public-key-output pgextassure-public-key.pem
```

The signer first performs the complete offline Evidence Bundle verification.
It then signs a statement binding:

- the exact bundle SHA-256 and byte size;
- the verified gate result;
- the evidence schema, manifest, coverage, and policy digests;
- the signature profile, public-key size, and DER public-key fingerprint;
- the signer ID and explicit creation date.

The private key is copied only into a mode-`0600` temporary file for the
OpenSSL operation. PgExtAssure does not log the key or passphrase. The original
key file must be a bounded regular non-symlink file.

## Verify

The recipient needs four files: the original evidence ZIP, canonical statement,
detached signature, and trusted public key.

```bash
pgextassure evidence verify-signature pgextassure-evidence.zip \
  --statement pgextassure-signature.json \
  --signature pgextassure-signature.bin \
  --public-key pgextassure-public-key.pem \
  --expected-key-sha256 'sha256:TRUSTED_64_HEX_DIGEST' \
  --format json
```

Verification fails unless all of the following succeed:

1. the Evidence Bundle passes its complete internal verification;
2. the statement has the exact schema and canonical JSON encoding;
3. the bundle bytes and verified metadata exactly match the statement;
4. the supplied public key matches the statement fingerprint and strength;
5. OpenSSL validates the RSA-PSS-SHA256 detached signature.

Exit code `0` means the signature chain is internally valid and, when
`--expected-key-sha256` is supplied, its public key matches that trust anchor.
Exit code `3` means verification failed. The recipient must obtain the expected
public-key fingerprint through an independent organizational trust channel;
the fingerprint inside the delivered statement is not a trust anchor.

## Key custody and non-claims

PgExtAssure does not generate, escrow, rotate, revoke, or distribute corporate
keys. Those responsibilities remain with the organization's PKI, KMS, HSM, or
security operations process. Profile 1.0 accepts a local PEM private key; direct
PKCS#11/KMS signing is not part of this profile.

A valid signature proves that the signed bundle and declared metadata have not
changed and that the holder of the corresponding private key produced the
signature. It does not certify the extension as safe, establish the legal
identity behind an untrusted key, or replace the organization's admission
authority.

To apply signer validity, revocation, evidence freshness, exact
tool/ruleset/policy constraints, and request-bound authorization, continue with
[Enterprise Trust Policy and Admission Receipt 1.0](enterprise-trust.md).
