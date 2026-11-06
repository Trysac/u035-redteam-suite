# Project record

## Objective

Provide a repeatable, dependency-free way to run a curated set of benign prompt injection, system prompt leak and jailbreak probes against an LLM target you own, and to report which probes succeeded, mapped to OWASP LLM01, LLM02 and LLM07.

## Scope

- In scope: the public API documented in [README.md](../README.md): the bundled 12-probe catalog, custom JSON catalogs, deterministic detectors, a runner with an injectable clock and event callback, a loopback-first HTTP target adapter, a test double, and the `redteam run` command line interface.
- Out of scope: attacker LLMs, multi-turn attacks, mitigation of findings, scanning systems you do not own, and anything that needs runtime dependencies or I/O without an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 500917 / 109008 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.8155 |

## Factory run u035 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2817 | 91568 | 0 | 4246 | 0.4611 |
| fix-1 | claude-sonnet-5-5 | no | 6 | 1068 | 7916 | 42247 | 0.0347 |
| fix-2 | claude-sonnet-5-5 | no | 12 | 2706 | 12302 | 102174 | 0.0681 |
| fix-3 | claude-sonnet-5-5 | no | 16 | 6642 | 18668 | 148043 | 0.1279 |
| fix-4 | claude-sonnet-5-5 | no | 10 | 1806 | 8881 | 75786 | 0.0479 |
| docs | claude-haiku-5-5 | no | 125560 | 5218 | 0 | 0 | 0.0758 |

Total: $0.8155. Prices: Anthropic list prices.
