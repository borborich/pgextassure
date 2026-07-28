# Contributing to PgExtAssure

Contributions that improve precision, explainability, portability, and safe
handling of untrusted input are welcome.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities through the [security policy](SECURITY.md), not a public
issue.

## Development setup

```bash
git clone https://github.com/borborich/pgextassure.git
cd pgextassure
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Proposing a change

1. Open an issue for substantial behavior or schema changes.
2. Create a focused branch and keep unrelated changes out of the pull request.
3. Add or update tests and documentation.
4. Run the complete test suite.
5. Explain the security assumptions, compatibility impact, and limitations in
   the pull request.

Rule changes should include:

- a stable, descriptive rule identifier;
- a vulnerable fixture and a safe counterexample;
- concise evidence and actionable remediation;
- an explanation of expected false positives and false negatives;
- deterministic output.

PgExtAssure must continue to treat the target extension tree as data. A
contribution must not build, import, install, or execute target-provided code as
part of the default static scan.

## Pull request checklist

- Tests pass on supported Python versions.
- New behavior is documented.
- Reports remain deterministic for identical inputs.
- No secrets, private fixtures, generated reports, or unrelated artifacts are
  committed.
- User-visible changes are added to [CHANGELOG.md](CHANGELOG.md).
