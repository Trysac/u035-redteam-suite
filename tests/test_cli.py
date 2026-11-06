from __future__ import annotations

import json
import sys
import types
from collections.abc import Callable

import pytest

from redteam_suite.__main__ import main
from redteam_suite.probes import load_probes
from redteam_suite.targets import HttpTarget
from redteam_suite.testing import FakeTarget

CANARY = "canary-7f3a9c1e"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class _Constant:
    def __init__(self, response: str) -> None:
        self._response = response

    def send(self, prompt: str) -> str:
        return self._response


class _Raising:
    def send(self, prompt: str) -> str:
        raise RuntimeError("x")


def _boom() -> object:
    raise RuntimeError("factory failed")


def _install(monkeypatch: pytest.MonkeyPatch, factory: Callable[[], object]) -> None:
    module = types.ModuleType("fake_target_mod")
    module.make = factory  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_target_mod", module)


def _run(capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, str, str]:
    argv = ["run", "--target", "fake_target_mod:make", "--canary", CANARY, *extra]
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_all_probes_resisted_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, lambda: FakeTarget({}))
    code, out, _ = _run(capsys)
    assert code == 0
    assert "0 of 12 probes succeeded" in out


def test_high_severity_success_exits_one_and_report_is_sorted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, lambda: _Constant(f"PWNED ZX-OVERRIDE-41 {CANARY} Sure!"))
    code, out, _ = _run(capsys, "--format", "json")
    payload = json.loads(out)
    assert code == 1
    assert payload["succeeded"] == 12
    ranks = [SEVERITY_RANK[item["severity"]] for item in payload["results"]]
    assert ranks == sorted(ranks)


def test_low_severity_success_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prompt = next(probe.prompt for probe in load_probes() if probe.id == "jbk-003")
    _install(monkeypatch, lambda: FakeTarget({prompt: "Sure!"}))
    code, out, _ = _run(capsys, "--format", "json")
    assert code == 0
    assert json.loads(out)["succeeded"] == 1


def test_category_filter_runs_only_jailbreak_probes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, lambda: FakeTarget({}))
    code, out, _ = _run(capsys, "--category", "jailbreak", "--format", "json")
    results = json.loads(out)["results"]
    assert code == 0
    assert len(results) == 3
    assert {item["category"] for item in results} == {"jailbreak"}


def test_probe_filter_runs_selected_probe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, lambda: FakeTarget({}))
    _, out, _ = _run(capsys, "--probe", "inj-001", "--format", "json")
    assert [item["probe_id"] for item in json.loads(out)["results"]] == ["inj-001"]


def test_unknown_category_and_probe_exit_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, lambda: FakeTarget({}))
    code, _, err = _run(capsys, "--category", "nope")
    assert code == 2
    assert "unknown category" in err
    code, _, err = _run(capsys, "--probe", "nope")
    assert code == 2
    assert "unknown probe" in err


def test_empty_selection_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, lambda: FakeTarget({}))
    code, _, err = _run(capsys, "--category", "jailbreak", "--probe", "inj-001")
    assert code == 2
    assert "no probes selected" in err


def test_raising_target_is_recorded_not_fatal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, _Raising)
    code, out, _ = _run(capsys, "--format", "json")
    assert code == 0
    assert {item["error"] for item in json.loads(out)["results"]} == {"RuntimeError: x"}
    code, out, _ = _run(capsys)
    assert code == 0
    assert "ERROR" in out


def test_text_output_lists_successes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, lambda: _Constant("Sure!"))
    code, out, _ = _run(capsys)
    assert code == 1
    assert "SUCCEEDED" in out
    assert "resisted" in out


@pytest.mark.parametrize(
    "spec",
    ["nocolon", "missing_module_xyz:make", "fake_target_mod:nope", ":make", "fake_target_mod:"],
)
def test_bad_target_specs_exit_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], spec: str
) -> None:
    _install(monkeypatch, lambda: FakeTarget({}))
    assert main(["run", "--target", spec, "--canary", CANARY]) == 2
    assert "error:" in capsys.readouterr().err


def test_failing_factory_and_target_without_send_exit_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, _boom)
    code, _, err = _run(capsys)
    assert code == 2
    assert "RuntimeError" in err
    _install(monkeypatch, object)
    code, _, err = _run(capsys)
    assert code == 2
    assert "send(prompt)" in err


def test_short_canary_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, lambda: FakeTarget({}))
    assert main(["run", "--target", "fake_target_mod:make", "--canary", "short"]) == 2
    assert "canary" in capsys.readouterr().err


def test_remote_url_is_refused_unless_allowed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(HttpTarget, "send", lambda self, prompt: "Sorry")
    argv = ["run", "--target-url", "http://example.com/x", "--canary", CANARY]
    assert main(argv) == 2
    assert "loopback" in capsys.readouterr().err
    assert main([*argv, "--allow-remote"]) == 0
    assert main(["run", "--target-url", "file:///etc/passwd", "--canary", CANARY]) == 2


def test_url_target_runs_probes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(HttpTarget, "send", lambda self, prompt: "Sorry, I cannot do that")
    code = main(["run", "--target-url", "http://127.0.0.1:9/x", "--canary", CANARY])
    assert code == 0
    assert "0 of 12 probes succeeded" in capsys.readouterr().out


def test_unreachable_url_target_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def down(self: HttpTarget, prompt: str) -> str:
        raise OSError("down")

    monkeypatch.setattr(HttpTarget, "send", down)
    code = main(["run", "--target-url", "http://127.0.0.1:9/x", "--canary", CANARY])
    captured = capsys.readouterr()
    assert code == 2
    assert "no probe could reach the target" in captured.err
    assert "OSError: down" in captured.out


def test_usage_errors_and_help(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([]) == 2
    assert main(["run", "--target", "a:b"]) == 2
    assert main(["run", "--canary", CANARY]) == 2
    assert main(["run", "--target", "a:b", "--target-url", "http://localhost/"]) == 2
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["redteam", "--help"])
    assert main() == 0
    assert "redteam" in capsys.readouterr().out
