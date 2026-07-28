# Security policy

PgExtAssure processes source trees that may be malicious. Security issues in
the scanner, GitHub Action, report generation, or release process should be
reported privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting form:

<https://github.com/borborich/pgextassure/security/advisories/new>

Please include:

- the affected PgExtAssure version or commit;
- the operating system and Python version;
- a minimal reproduction or proof of concept;
- the expected and observed behavior;
- the potential security impact.

Do not include credentials, private source, or sensitive report excerpts unless
they are necessary to reproduce the issue. Do not open a public issue for an
unpatched vulnerability.

The maintainers will acknowledge the report as soon as practical, investigate
it, and coordinate disclosure and remediation with the reporter. No response
or remediation SLA is currently offered.

## Scope

Examples of in-scope reports include:

- escaping the requested scan root;
- executing content from the target extension tree;
- unsafe handling of symlinks, paths, encodings, or terminal output;
- denial-of-service behavior that bypasses documented resource boundaries;
- report injection with a concrete security impact;
- release or GitHub Action supply-chain vulnerabilities.

A false positive, false negative, or rule bypass without a demonstrated
security boundary violation is normally a correctness issue and may be filed as
a regular bug. Security findings in a third-party PostgreSQL extension should
be reported to that project's maintainers under its disclosure policy.

## Supported versions

Security fixes are applied to the latest released version and the default
branch. Older releases may not receive backports.
