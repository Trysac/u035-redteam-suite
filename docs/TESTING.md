# Testing

## Running

```sh
uv run pytest --cov=redteam_suite   # tests with coverage report
uv run python scripts/check.py      # every gate, as CI and the factory run it
```

## Policy

- Branch coverage of `src/redteam_suite` must stay at or above 80 %; the gate fails below it.
- Tests exercise the public API (`import redteam_suite`) and assert every observable effect: return values, raised exceptions and their messages.
- Each bug fix starts with a failing test that reproduces it.
- Tests are deterministic: no network, no wall clock, no dependence on test order.

## Layout

`tests/test_<module>.py` mirrors each public module. Shared fixtures go in `tests/conftest.py`.

## Scope of the existing tests

The acceptance criteria in the specification are the basis for the test suite: catalog loading and rejection of malformed catalogs, one send per probe with an injected clock, canary and marker boundary matching with normalisation, no_refusal behaviour, category and probe filters, CLI exit codes, the `HttpTarget` host, scheme and redirect rules, the response size limit, and the absence of header values from events, reports and errors.
