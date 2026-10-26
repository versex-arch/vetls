# Contributing

Thanks for helping out. The project is small; the process is too.

## Setup

```bash
git clone https://github.com/versex-arch/vetls.git
cd vetls
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request

```bash
pytest          # tests talk to real servers on 127.0.0.1, no internet needed
ruff check .
ruff format --check .
mypy
```

## Ground rules

- **No fake data.** Every reported value must come from a real handshake, certificate or banner.
  Please do not add hand-typed lists such as "vulnerable software versions".
- **Untestable is not secure and not insecure.** If the local OpenSSL build cannot attempt something,
  report it as unchecked. It must never change the severity.
- **Fixed schemas.** Error results carry the same keys as successful ones.
- **Test with real sockets** where practical. A test that only inspects source code is not a test.
- A bug fix comes with a test that fails without it.
- **Stable rule IDs.** A new rule gets a new ID in `vetls.scorer.RULES`; never rename or reuse an ID,
  people put them in `--ignore` lists.
- User-visible changes go into [CHANGELOG.md](CHANGELOG.md) under "Unreleased".

## Releasing

1. Bump `__version__` in `src/vetls/__init__.py` and move the changelog entries under the new version.
2. Tag and push: `git tag v1.2.3 && git push --tags`. The release workflow tests, builds and publishes to PyPI
   through Trusted Publishing, then creates the GitHub release.

## Reporting bugs

Open an issue with the command you ran, the output (`--json` is ideal) and your Python and OpenSSL
versions (`python -c "import ssl, sys; print(sys.version, ssl.OPENSSL_VERSION)"`).
Security problems: see [SECURITY.md](SECURITY.md).
