# Security questionnaire: concise pilot answers

## Does PgExtAssure execute the extension?

No. Static scanning treats the target as data. It does not run Make, Cargo,
compilers, package hooks, target scripts, SQL, imports, or shared libraries.

## Is source code uploaded?

No upload is performed by the CLI. Evidence Bundle 1.0 contains no source-file
payloads. Reports do retain paths and bounded matched excerpts, so artifacts
must be protected as security-sensitive.

## Does offline verification require a vendor service?

No. Bundle verification uses PgExtAssure locally. Corporate signature
verification uses a local OpenSSL executable. Neither operation requires
GitHub, OIDC, Sigstore, telemetry, or a PgExtAssure account.

## What is cryptographically signed?

A canonical statement binds the exact evidence ZIP digest and size, verified
gate, evidence schema, source-manifest digest, coverage digest, policy digest,
signer ID, date, signature profile, and public-key fingerprint.

## Which signature algorithm is accepted?

Corporate Evidence Signature Profile 1.0 accepts RSA-PSS with SHA-256 and RSA
keys of at least 3072 bits. The public key is normalized as X.509
SubjectPublicKeyInfo.

## How is signer identity established?

The signature proves possession of the matching private key. The receiving
organization must trust the expected public-key fingerprint through its own
PKI or an independent delivery channel. A self-presented signer ID is not an
identity proof.

## Where are private keys stored?

PgExtAssure does not store or manage keys. The signing command accepts a
bounded local PEM file, uses a mode-`0600` temporary copy for OpenSSL, and
removes the temporary directory after the operation. Key lifecycle remains an
organizational responsibility.

## Are encrypted private keys supported?

Yes. The passphrase is read from a named environment variable and passed to
OpenSSL through a private child-process environment. It is not included in the
command line or output.

## Can a blocked result be signed?

Yes. Signing preserves evidence rather than manufacturing approval. A valid
signature over `"gate": "blocked"` proves integrity of a blocked decision.

## Does a valid result certify that an extension is safe?

No. PgExtAssure produces review evidence, not certification, formal
verification, legal advice, or automatic installation authority.

## What remains outside the static pilot?

Runtime behavior, compiled-artifact/source correspondence, transitive
dependency resolution, memory safety, malicious build systems, operational
configuration, and the security of the runner, Python, OpenSSL, and selected
PgExtAssure distribution remain separate controls.
