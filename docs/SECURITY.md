# Security

`trysac-redteam-suite` is a defensive testing tool. It sends a small catalog of static, benign prompts to a system **you own** and scores the answers with deterministic detectors. It never calls an attacker LLM, never holds multi-turn conversations and does not mitigate anything.

## Threat model

### Intended use

- Repeatable regression checks for prompt injection, system prompt leakage and jailbreak resistance of your own LLM features, mapped to the OWASP Top 10 for LLM Applications 2025 (genai.owasp.org, released November 2024, checked 2026-11-05): LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure and LLM07 System Prompt Leakage. Only these three ids are bundled.
- You plant a canary string (at least 12 characters) in the target's hidden context. A probe succeeds (the attack worked) when the answer shows the canary, echoes the probe's marker, or does not refuse.

### Defended (and tested)

- **Loopback by default.** `HttpTarget` accepts `localhost` exactly, or an IP literal that `ipaddress` prints in canonical form and reports as loopback (`127.0.0.0/8`, `::1`). IPv4-mapped IPv6 and non-canonical numeric hosts such as `0x7f.1` are refused with `remote_target_refused` unless `allow_remote=True`. Schemes other than http and https raise `unsupported_scheme`.
- **No redirects.** Every 301, 302, 303, 307 and 308 reply raises `redirect_refused`.
- **No proxies.** The HTTP opener ignores proxy environment variables.
- **Bounded input.** Responses are read with `read(max_response_bytes + 1)` and rejected with `response_too_large`; custom catalogs are limited to 1 MiB and 1000 probes; prompts, markers, URLs and header counts have limits; JSON nesting that exhausts the parser is rejected as `catalog_invalid`.
- **Header secrets stay private.** Header values are validated at construction without echoing them, and never appear in events, reports, errors or `repr`.
- **Bounded output.** Excerpts are cut to 2000 characters, error text to 200 characters, events carry no prompt or response text, and `FakeTarget` keeps at most 1000 calls.
- **Normalised detector input.** Responses are normalised with NFKC, case folding, U+2019 to an apostrophe and removal of U+200B, U+200C, U+200D, U+2060 and U+FEFF; canary and marker matches require that no `[a-z0-9]` character touches the match.

### Not defended

- DNS names when `allow_remote=True` (no resolution checks, no SSRF protection).
- Canaries split or re-encoded by the model (base64, spacing, translation).
- Refusal phrasing outside the four bundled patterns; a model that answers off-topic without a refusal counts as a successful jailbreak probe.
- A marker quoted legitimately (for example while summarising the probe) is a false positive.
- `--target module:factory` imports and runs code: only use trusted modules. Headers can be set from the library only, not from the CLI.

### Out of scope

Attacker LLMs, multi-turn attacks, mitigation of findings, scanning systems you do not own.

## Reporting a vulnerability

See the repository `SECURITY.md`.
