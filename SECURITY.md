# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in SwarmNoise, please report it privately:

- Open a [GitHub Security Advisory](https://github.com/fabs-net/swarmnoise/security/advisories/new)
- Or email the maintainer directly via their GitHub profile

**Do not file a public issue for security vulnerabilities.**

## What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

## Response timeline

- Acknowledgment within 48 hours
- Initial assessment within 5 business days
- Fix or mitigation plan within 14 business days

## Scope

This policy covers the SwarmNoise codebase, including:

- `scripts/fetch_sessions.py`
- `scripts/scheduler.py`
- `scripts/archive_month.py`
- GitHub Actions workflows

Out of scope:

- GreyNoise API vulnerabilities (report to GreyNoise directly)
- Third-party dependencies (report upstream)

## Best practices

- Never commit API keys, tokens, or credentials to the repository.
- Use GitHub Secrets for all sensitive configuration.
- Rotate credentials if they have been exposed.
