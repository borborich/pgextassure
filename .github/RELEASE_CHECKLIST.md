# PgExtAssure release checklist

Use this checklist for every public GitHub and GitHub Marketplace release.

## Before tagging

- [ ] Confirm the release owner, canonical repository slug, and Marketplace
      action name.
- [ ] Confirm the public release/tag version follows semantic versioning and
      corresponds to the PEP 440 package version (for example,
      `0.1.0-alpha.1` and `0.1.0a1`).
- [ ] Review all changes since the previous release and prepare release notes
      that clearly identify breaking changes, security fixes, rule changes, and
      known limitations.
- [ ] Confirm `main` is protected and the CI workflow is required.
- [ ] Confirm every external GitHub Action is pinned to a reviewed full commit
      SHA and its version comment matches the official release.
- [ ] Run secret and PII scanning over the full Git history and current
      worktree.
- [ ] Confirm `SECURITY.md`, the license, CODEOWNERS, and public support paths
      are current.
- [ ] Run the complete CI matrix on Python 3.11, 3.12, 3.13, and 3.14.
- [ ] Confirm the composite Action end-to-end job validates SARIF, JSON, file
      output, stdout mode, paths with spaces, and a blocking `fail-on` result.
- [ ] Confirm wheel and sdist builds are byte-identical across Python 3.11 and
      3.14, install offline in fresh environments, and pass CLI/module smoke
      scans.
- [ ] Record and independently verify SHA-256 checksums for release artifacts.
- [ ] Confirm benchmark and documentation claims identify the exact scanner
      version, ruleset version, source revision, and artifact digest.

## Tag and release

- [ ] Create an annotated tag `vX.Y.Z` from the reviewed release commit. Sign
      stable tags; if an alpha tag is unsigned, record that explicitly in its
      release notes.
- [ ] Verify the tag version matches the public release version and maps to the
      package's PEP 440 version.
- [ ] Create the GitHub release from that tag and attach the verified wheel,
      sdist, and `SHA256SUMS`.
- [ ] Mark prereleases accurately; do not move a patch tag after publication.
- [ ] For a stable Marketplace release, select **Publish this Action to the
      GitHub Marketplace**, verify its categories and branding, and accept the
      Marketplace Developer Agreement using an account protected by 2FA.
- [ ] After the immutable patch release is published, update the supported
      floating major tag (for example `v0`) only according to the documented
      compatibility policy.

## After release

- [ ] Install the published wheel and sdist by immutable version in clean
      environments and repeat the safe-fixture smoke scan.
- [ ] Invoke the Action from an unrelated clean repository using the immutable
      release commit SHA and the documented major tag.
- [ ] Verify Marketplace inputs, default output path, branding, and example
      workflow.
- [ ] Publish release notes and checksums, then monitor security reports and
      installation failures.
