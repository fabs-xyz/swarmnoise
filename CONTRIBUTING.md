# Contributing to SwarmNoise

Thanks for your interest in improving SwarmNoise.

## Reporting issues

- Use [GitHub Issues](https://github.com/fabs-net/swarmnoise/issues) for bugs and feature requests.
- Include Python version, OS, and relevant log output when reporting bugs.
- **Never post real IP addresses, API keys, or sensor IDs** in issues. Use RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in examples.

## Development setup

```bash
git clone https://github.com/fabs-net/swarmnoise.git
cd swarmnoise
pip install -r requirements.txt
pip install pytest requests-mock
```

## Running tests

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a pull request.

## Pull requests

1. Fork the repository and create a feature branch.
2. Make your changes with clear, atomic commits.
3. Add or update tests for any changed behavior.
4. Ensure `pytest` passes.
5. Open a pull request with a description of the change and motivation.

## Code style

- Follow PEP 8. Use `ruff` for linting if available.
- Keep functions focused and under ~40 lines.
- Use descriptive variable and function names.
- No bare `except:` or `except Exception:` — catch specific exceptions.

## Security

- Never commit secrets, tokens, or credentials.
- See [SECURITY.md](SECURITY.md) for vulnerability reporting.
