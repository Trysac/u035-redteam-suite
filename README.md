# redteam-suite

[![PyPI version](https://img.shields.io/pypi/v/trysac-redteam-suite)](https://pypi.org/project/trysac-redteam-suite/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-redteam-suite)](LICENSE)
[![CI](https://github.com/Trysac/u035-redteam-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u035-redteam-suite/actions/workflows/ci.yml)

Run a versioned battery of benign prompt injection, system prompt leak and jailbreak probes against a target you own and report findings

## Problem

LLM features ship without a repeatable adversarial test, so prompt injection or system prompt leaks are found by users. Full red-teaming platforms need accounts and attacker LLMs. This library and CLI run a small curated set of static probes, mapped to the OWASP Top 10 for LLM Applications 2025, against a target adapter you control and score the answers with deterministic detectors.

## Install

```sh
pip install trysac-redteam-suite
# or
uv add trysac-redteam-suite
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
from redteam_suite import load_probes, run_suite
from redteam_suite.testing import FakeTarget

probes = load_probes()
report = run_suite(FakeTarget({}), probes, canary="canary-7f3a9c1e")
print(report.succeeded_count, "of", len(report.results), "probes succeeded")
print(report.to_json()[:80])
# CLI: python -m redteam_suite run --target-url http://localhost:8000/chat --canary canary-7f3a9c1e
```

## Public API

- `load_probes(path: Path | None = None) -> list[Probe]`: loads the bundled catalog of 12 probes, or a custom JSON catalog (at most 1 MiB and 1000 probes).
- `select_probes(probes, categories=(), ids=())`: filters by category and id, keeping catalog order.
- `Probe`: frozen dataclass with `id`, `category`, `severity`, `owasp`, `prompt`, `detector` and optional `marker`.
- `Target`: protocol with `send(prompt: str) -> str`.
- `HttpTarget(url, field='prompt', response_field='output', headers=None, timeout=30.0, allow_remote=False, max_response_bytes=1_048_576)`: POSTs JSON to an HTTP endpoint. Loopback hosts only unless `allow_remote=True`.
- `run_suite(target, probes, canary, clock=time.monotonic, on_event=None) -> SuiteReport`: sends each probe once, in order, and scores the answer. A target exception is recorded on the result and the run continues.
- `SuiteReport`: `results` ordered by severity then probe id, `succeeded_count`, `has_blocking_success`, `to_json()`.
- `ProbeResult`, `ProbeEvent`: per-probe outcome and progress notification (no prompt or response text in events).
- `RedteamError`: base error with a stable `code`: `catalog_invalid`, `unknown_probe`, `unknown_category`, `remote_target_refused`, `unsupported_scheme`, `redirect_refused`, `response_too_large`.

Errors: an invalid canary (shorter than 12 characters or longer than 512) raises `ValueError`.

Limits: prompts up to 10,000 characters, markers up to 200 characters, responses up to `max_response_bytes`, excerpts cut to 2000 characters, error text cut to 200 characters.

CLI: `redteam run (--target-url URL | --target module:factory) --canary TOKEN [--category C]... [--probe ID]... [--format text|json] [--allow-remote]`. Exit codes: 0 no high or critical success, 1 at least one high or critical success, 2 usage, catalog or connection error. `--target` imports and runs trusted code.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model, including what is defended and what is not.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
