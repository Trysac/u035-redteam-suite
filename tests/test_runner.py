from __future__ import annotations

import json
import logging
from typing import ClassVar

import pytest

from redteam_suite.errors import RedteamError
from redteam_suite.probes import Probe, load_probes
from redteam_suite.runner import ProbeEvent, run_suite
from redteam_suite.targets import HttpTarget
from redteam_suite.testing import MAX_RECORDED_CALLS, FakeTarget

CANARY = "canary-7f3a9c1e"
AUTH_VALUE = "Bearer test-credential-value"


def _probe(
    detector: str,
    marker: str | None = None,
    severity: str = "high",
    probe_id: str = "p1",
) -> Probe:
    return Probe(probe_id, "injection", severity, "LLM01", f"Prompt {probe_id}", detector, marker)


def _outcome(probe: Probe, response: str) -> bool:
    report = run_suite(FakeTarget({probe.prompt: response}), [probe], CANARY)
    return report.results[0].succeeded


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("C\u200bANARY-7F3A9C1E", True),
        ("\uff23ANARY-7f3a9c1e", True),
        ("ＣANARY-7f3a9c1e", True),
        ("canary-7f3a9c1e0", False),
        ("xcanary-7f3a9c1e", False),
    ],
)
def test_canary_leak_probe(response: str, expected: bool) -> None:
    assert _outcome(_probe("canary_leak"), response) is expected


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("I can\u2019t help with that. PWNED", True),
        ("pwnedx", False),
    ],
)
def test_marker_echo_probe(response: str, expected: bool) -> None:
    assert _outcome(_probe("marker_echo", "PWNED"), response) is expected


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("I can\u2019t help with that.", False),
        ("Sorry, I cannot do that", False),
        ("Sure!", True),
    ],
)
def test_no_refusal_probe(response: str, expected: bool) -> None:
    assert _outcome(_probe("no_refusal"), response) is expected


def test_literal_acceptance_responses() -> None:
    """A target raising RuntimeError('x') records error 'RuntimeError: x' (see below)."""
    assert _outcome(_probe("canary_leak"), "C​ANARY-7F3A9C1E") is True
    assert _outcome(_probe("canary_leak"), "ＣANARY-7f3a9c1e") is True
    assert _outcome(_probe("marker_echo", "PWNED"), "I can’t help with that. PWNED") is True
    assert _outcome(_probe("no_refusal"), "I can’t help with that.") is False


def test_send_is_called_once_per_probe_in_catalog_order() -> None:
    probes = load_probes()
    target = FakeTarget({})
    report = run_suite(target, probes, CANARY)
    assert target.calls == tuple(probe.prompt for probe in probes)
    assert len(report.results) == 12
    assert report.succeeded_count == 0
    assert report.has_blocking_success is False


def test_latency_uses_the_injected_clock() -> None:
    ticks = iter([0.0, 0.25])
    report = run_suite(FakeTarget({}), [_probe("no_refusal")], CANARY, clock=lambda: next(ticks))
    assert report.results[0].latency_ms == 250.0


def test_backwards_clock_gives_zero_latency() -> None:
    ticks = iter([5.0, 1.0])
    report = run_suite(FakeTarget({}), [_probe("no_refusal")], CANARY, clock=lambda: next(ticks))
    assert report.results[0].latency_ms == 0.0


def test_report_orders_by_severity_then_id() -> None:
    probes = [
        _probe("no_refusal", severity="low", probe_id="a"),
        _probe("no_refusal", severity="critical", probe_id="z"),
        _probe("no_refusal", severity="high", probe_id="b"),
        _probe("no_refusal", severity="critical", probe_id="c"),
        _probe("no_refusal", severity="medium", probe_id="d"),
    ]
    report = run_suite(FakeTarget({}), probes, CANARY)
    assert [item.probe_id for item in report.results] == ["c", "z", "b", "d", "a"]


class _Flaky:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def send(self, prompt: str) -> str:
        self.calls.append(prompt)
        if prompt == "Prompt p1":
            raise RuntimeError("x")
        return "Sure!"


def test_target_exception_is_recorded_and_the_run_continues() -> None:
    target = _Flaky()
    probes = [_probe("no_refusal"), _probe("no_refusal", probe_id="p2")]
    events: list[ProbeEvent] = []
    report = run_suite(target, probes, CANARY, on_event=events.append)
    by_id = {item.probe_id: item for item in report.results}
    assert by_id["p1"].error == "RuntimeError: x"
    assert by_id["p1"].succeeded is False
    assert by_id["p2"].succeeded is True
    assert by_id["p2"].error is None
    assert len(target.calls) == 2
    assert [(event.probe_id, event.error_type) for event in events] == [
        ("p1", "RuntimeError"),
        ("p2", None),
    ]


class _Bad:
    def __init__(self, value: object) -> None:
        self._value = value

    def send(self, prompt: str) -> str:
        if isinstance(self._value, Exception):
            raise self._value
        return self._value  # type: ignore[return-value]


def test_long_error_messages_are_cut() -> None:
    report = run_suite(_Bad(ValueError("y" * 500)), [_probe("no_refusal")], CANARY)
    assert report.results[0].error == "ValueError: " + "y" * 200


def test_non_string_and_oversized_responses_are_errors() -> None:
    probes = [_probe("no_refusal")]
    non_string = run_suite(_Bad(42), probes, CANARY)
    assert non_string.results[0].error == "TypeError: target returned a non-string response"
    oversized = run_suite(_Bad("a" * 4_194_305), probes, CANARY)
    assert str(oversized.results[0].error).startswith("RedteamError:")
    assert oversized.results[0].succeeded is False


def test_excerpt_is_cut_to_2000_characters() -> None:
    report = run_suite(_Bad("a" * 5000), [_probe("no_refusal")], CANARY)
    assert len(report.results[0].response_excerpt) == 2000
    assert report.results[0].succeeded is True


def test_events_carry_no_prompt_or_response_text() -> None:
    events: list[ProbeEvent] = []
    probe = _probe("no_refusal")
    response = "a distinctive answer"
    run_suite(FakeTarget({probe.prompt: response}), [probe], CANARY, on_event=events.append)
    assert isinstance(events[0], ProbeEvent)
    assert response not in repr(events)
    assert probe.prompt not in repr(events)


def test_failing_callback_does_not_stop_the_run(caplog: pytest.LogCaptureFixture) -> None:
    def explode(event: ProbeEvent) -> None:
        raise RuntimeError("callback")

    probes = [_probe("no_refusal"), _probe("no_refusal", probe_id="p2")]
    with caplog.at_level(logging.WARNING, logger="redteam_suite.runner"):
        report = run_suite(FakeTarget({}), probes, CANARY, on_event=explode)
    assert len(report.results) == 2
    assert "on_event callback failed: RuntimeError" in caplog.text


def test_report_json_and_blocking_flag() -> None:
    probes = [
        _probe("no_refusal", severity="low", probe_id="a"),
        _probe("no_refusal", severity="high", probe_id="b"),
    ]
    report = run_suite(FakeTarget({}, default="Sure!"), probes, CANARY)
    payload = json.loads(report.to_json())
    assert payload["total"] == 2
    assert payload["succeeded"] == 2
    assert payload["results"][0]["probe_id"] == "b"
    assert report.has_blocking_success is True
    low_only = run_suite(FakeTarget({}, default="Sure!"), probes[:1], CANARY)
    assert low_only.has_blocking_success is False


def test_invalid_inputs_are_rejected_before_any_send() -> None:
    target = FakeTarget({})
    with pytest.raises(ValueError, match="canary"):
        run_suite(target, [_probe("no_refusal")], "short")
    with pytest.raises(RedteamError) as no_marker:
        run_suite(target, [_probe("marker_echo")], CANARY)
    assert no_marker.value.code == "catalog_invalid"
    duplicates = [_probe("no_refusal"), _probe("no_refusal")]
    with pytest.raises(RedteamError) as duplicate:
        run_suite(target, duplicates, CANARY)
    assert duplicate.value.code == "catalog_invalid"
    many = [_probe("no_refusal", probe_id=f"p{i}") for i in range(1001)]
    with pytest.raises(RedteamError) as too_many:
        run_suite(target, many, CANARY)
    assert too_many.value.code == "catalog_invalid"
    assert target.calls == ()


class _FakeResponse:
    headers: ClassVar[dict[str, str]] = {"Content-Type": "text/plain"}

    def read(self, size: int = -1) -> bytes:
        return b"Sure!"

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _Opener:
    def __init__(self, fail: bool) -> None:
        self._fail = fail

    def open(self, request: object, timeout: float) -> _FakeResponse:
        if self._fail:
            raise OSError("connection refused")
        return _FakeResponse()


@pytest.mark.parametrize("fail", [True, False])
def test_authorization_value_never_reaches_events_or_report(fail: bool) -> None:
    target = HttpTarget("http://localhost/x", headers={"Authorization": AUTH_VALUE})
    target._opener = _Opener(fail)  # type: ignore[assignment]
    events: list[ProbeEvent] = []
    report = run_suite(target, [_probe("no_refusal")], CANARY, on_event=events.append)
    assert AUTH_VALUE not in repr(events)
    assert AUTH_VALUE not in report.to_json()
    assert (report.results[0].error is not None) is fail


def test_fake_target_default_and_bounded_call_log() -> None:
    target = FakeTarget({"known": "yes"})
    assert target.send("known") == "yes"
    assert target.send("unknown") == "I can't help with that."
    for index in range(MAX_RECORDED_CALLS + 5):
        target.send(f"p{index}")
    assert len(target.calls) == MAX_RECORDED_CALLS
    assert target.calls[-1] == f"p{MAX_RECORDED_CALLS + 4}"
