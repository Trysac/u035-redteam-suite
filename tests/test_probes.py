from __future__ import annotations

import importlib.resources
import json
from pathlib import Path

import pytest

from redteam_suite.errors import RedteamError
from redteam_suite.probes import (
    MAX_CATALOG_BYTES,
    MAX_PROBES,
    Probe,
    load_probes,
    select_probes,
    validate_probe,
)


def _probe(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "p1",
        "category": "injection",
        "severity": "low",
        "owasp": "LLM01",
        "prompt": "Say hi",
        "detector": "no_refusal",
    }
    base.update(overrides)
    return base


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _code(path: Path) -> str:
    with pytest.raises(RedteamError) as info:
        load_probes(path)
    return info.value.code


def test_bundled_catalog_has_twelve_probes_three_per_category() -> None:
    probes = load_probes()
    assert len(probes) == 12
    assert len({probe.id for probe in probes}) == 12
    assert len({probe.prompt for probe in probes}) == 12
    for category in ("injection", "system_leak", "jailbreak", "data_exfil"):
        assert sum(1 for probe in probes if probe.category == category) == 3
    assert {probe.owasp for probe in probes} <= {"LLM01", "LLM02", "LLM07"}
    assert any(probe.severity in ("high", "critical") for probe in probes)


def test_bundled_catalog_has_a_version_field() -> None:
    resource = importlib.resources.files("redteam_suite").joinpath("probes.json")
    document = json.loads(resource.read_bytes())
    assert isinstance(document["version"], str)
    assert document["version"]


def test_custom_catalog_object_and_bare_list(tmp_path: Path) -> None:
    as_object = _write(tmp_path, {"version": "2", "probes": [_probe()]})
    assert [probe.id for probe in load_probes(as_object)] == ["p1"]
    as_list = _write(tmp_path, [_probe(detector="marker_echo", marker="PWNED")])
    assert load_probes(as_list)[0].marker == "PWNED"


def test_duplicate_id_is_invalid(tmp_path: Path) -> None:
    path = _write(tmp_path, {"version": "1", "probes": [_probe(), _probe()]})
    assert _code(path) == "catalog_invalid"


@pytest.mark.parametrize(
    "probe",
    [
        _probe(owasp="LLM05"),
        _probe(detector="semantic_judge"),
        _probe(detector="marker_echo"),
        _probe(detector="marker_echo", marker=""),
        _probe(detector="marker_echo", marker="\u200b"),
        _probe(detector="marker_echo", marker=5),
        _probe(marker="x" * 201),
        _probe(category="nope"),
        _probe(severity="urgent"),
        _probe(id=""),
        _probe(id="bad id"),
        _probe(id=7),
        _probe(prompt="   "),
        _probe(prompt=3),
        _probe(prompt="x" * 10_001),
        _probe(extra="field"),
    ],
)
def test_invalid_probe_is_rejected(tmp_path: Path, probe: dict[str, object]) -> None:
    path = _write(tmp_path, {"version": "1", "probes": [probe]})
    assert _code(path) == "catalog_invalid"


@pytest.mark.parametrize(
    "document",
    [
        {"probes": "x"},
        {"version": "1"},
        {"version": 3, "probes": []},
        [1],
        [{"id": "p1"}],
        5,
    ],
)
def test_invalid_structure_is_rejected(tmp_path: Path, document: object) -> None:
    assert _code(_write(tmp_path, document)) == "catalog_invalid"


def test_unreadable_or_malformed_files_are_rejected(tmp_path: Path) -> None:
    assert _code(tmp_path / "missing.json") == "catalog_invalid"
    assert _code(tmp_path) == "catalog_invalid"
    bad_utf8 = tmp_path / "bad.json"
    bad_utf8.write_bytes(b"\xff\xfe")
    assert _code(bad_utf8) == "catalog_invalid"
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert _code(broken) == "catalog_invalid"


def test_deeply_nested_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "deep.json"
    path.write_bytes(b"[" * 100_000)
    assert _code(path) == "catalog_invalid"


def test_size_limit(tmp_path: Path) -> None:
    prefix = b'{"probes": []}'
    exact = tmp_path / "exact.json"
    exact.write_bytes(prefix + b" " * (MAX_CATALOG_BYTES - len(prefix)))
    assert load_probes(exact) == []
    over = tmp_path / "over.json"
    over.write_bytes(prefix + b" " * (MAX_CATALOG_BYTES - len(prefix) + 1))
    assert _code(over) == "catalog_invalid"


def test_probe_count_limit(tmp_path: Path) -> None:
    ok = _write(tmp_path, [_probe(id=f"p{i}") for i in range(MAX_PROBES)])
    assert len(load_probes(ok)) == MAX_PROBES
    too_many = _write(tmp_path, [_probe(id=f"p{i}") for i in range(MAX_PROBES + 1)])
    assert _code(too_many) == "catalog_invalid"


def test_validate_probe_accepts_good_and_rejects_bad() -> None:
    good = Probe("p1", "injection", "low", "LLM01", "Say hi", "marker_echo", "PWNED")
    validate_probe(good)
    bad = Probe("p1", "injection", "low", "LLM01", "Say hi", "marker_echo")
    with pytest.raises(RedteamError) as info:
        validate_probe(bad)
    assert info.value.code == "catalog_invalid"


def test_select_probes_filters_and_keeps_order() -> None:
    probes = load_probes()
    jailbreaks = select_probes(probes, ["jailbreak"])
    assert [probe.id for probe in jailbreaks] == ["jbk-001", "jbk-002", "jbk-003"]
    assert [probe.id for probe in select_probes(probes, ids=["exf-001", "inj-001"])] == [
        "inj-001",
        "exf-001",
    ]
    assert select_probes(probes, ["jailbreak"], ["inj-001"]) == []
    assert select_probes(probes) == probes


def test_select_probes_unknown_values() -> None:
    probes = load_probes()
    with pytest.raises(RedteamError) as category_info:
        select_probes(probes, ["nope"])
    assert category_info.value.code == "unknown_category"
    with pytest.raises(RedteamError) as probe_info:
        select_probes(probes, ids=["nope"])
    assert probe_info.value.code == "unknown_probe"
