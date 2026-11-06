# redteam-suite

[![PyPI version](https://img.shields.io/pypi/v/trysac-redteam-suite)](https://pypi.org/project/trysac-redteam-suite/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-redteam-suite)](LICENSE)
[![CI](https://github.com/Trysac/u035-redteam-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u035-redteam-suite/actions/workflows/ci.yml)

Run a versioned battery of benign prompt injection, system prompt leak and jailbreak probes against a target you own and report findings

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-redteam-suite
# or
uv add trysac-redteam-suite
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import redteam_suite

# normalize() trims surrounding whitespace and lower-cases the text.
print(redteam_suite.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    redteam_suite.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
