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
| Tokens (input / output) | pending measurement |
| Hours (human) | pending measurement |
| Cost (USD) | pending measurement |
