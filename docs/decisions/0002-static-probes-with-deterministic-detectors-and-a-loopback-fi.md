# Static probes with deterministic detectors and a loopback-first HTTP adapter

Status: accepted (generated, pending human review)

## Context

LLM features ship without a repeatable adversarial test, while full red-teaming platforms need accounts and attacker LLMs. The tool must be reproducible, offline testable and safe to run from a developer machine against a system the user owns, without becoming an SSRF or exfiltration helper.

## Decision

Ship a small curated catalog of benign static probes as package data, score answers with three pure detectors (canary_leak, marker_echo, no_refusal) on NFKC/casefold/zero-width normalised text with alphanumeric boundaries, and talk to targets through a minimal Target protocol. HttpTarget uses only urllib, accepts loopback hosts by default (exact localhost or canonical loopback IP literals), refuses redirects, ignores proxies, caps response size and validates header values so they never reach errors. Clocks, targets and events are injected so tests need no network or real time.

## Consequences

Results are deterministic and the library has no runtime dependencies. Detection is limited to literal canaries, markers and a fixed refusal list, so re-encoded leaks and unusual refusals are missed; this is documented in the threat model. Remote DNS targets need an explicit allow_remote opt-in with no further protection. Adding probes or detectors later requires a catalog version bump.
