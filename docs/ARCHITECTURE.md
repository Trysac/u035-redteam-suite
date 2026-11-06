# Architecture

## Purpose

`trysac-redteam-suite` is a small, dependency-free Python library that runs a versioned battery of benign prompt injection, system prompt leak and jailbreak probes against a target you own and reports findings.

## Shape

```text
caller code / CLI --> redteam_suite (public API in __init__.py)
                          |
                          +-- probes.py   catalog loading and validation (probes.json)
                          +-- detectors.py deterministic response scoring
                          +-- targets.py  Target protocol and HttpTarget (loopback first)
                          +-- runner.py   run_suite, ProbeResult, SuiteReport
                          +-- errors.py   RedteamError with stable codes
                          +-- testing.py  FakeTarget test double
```

- **Public API**: the names listed in `__all__` of `src/redteam_suite/__init__.py`. Anything else is internal.
- **Errors**: catalog and target failures raise `RedteamError` with a stable `code`; invalid canary values raise `ValueError`.
- **Side effects**: `HttpTarget` performs HTTP requests; `load_probes` reads package data or a file path; the library otherwise has no global state. `__main__.py` implements the CLI and prints output.
- **Logging**: the package logger uses a `NullHandler`.

## Quality contract

`scripts/check.py` is the single definition of the gates; `fabrica.json` tells the factory and CI how to run it. See [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
