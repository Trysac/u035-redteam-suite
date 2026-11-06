"""Probe model, bundled catalog loader and probe selection."""

from __future__ import annotations

import importlib.resources
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, get_args

from .detectors import DetectorName, normalize
from .errors import RedteamError

Category = Literal["injection", "system_leak", "jailbreak", "data_exfil"]
Severity = Literal["low", "medium", "high", "critical"]
Owasp = Literal["LLM01", "LLM02", "LLM07"]

CATEGORIES: tuple[str, ...] = get_args(Category)
SEVERITIES: tuple[str, ...] = get_args(Severity)
OWASP_IDS: tuple[str, ...] = get_args(Owasp)
DETECTORS: tuple[str, ...] = get_args(DetectorName)

MAX_CATALOG_BYTES = 1_048_576
MAX_PROBES = 1000
MAX_PROMPT_CHARS = 10_000
MAX_MARKER_CHARS = 200

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_REQUIRED_FIELDS = frozenset({"id", "category", "severity", "owasp", "prompt", "detector"})
_ALLOWED_FIELDS = _REQUIRED_FIELDS | {"marker"}


@dataclass(frozen=True)
class Probe:
    """One static, benign adversarial prompt and the detector that scores the answer."""

    id: str
    category: Category
    severity: Severity
    owasp: Owasp
    prompt: str
    detector: DetectorName
    marker: str | None = None


def _invalid(message: str) -> RedteamError:
    return RedteamError("catalog_invalid", message)


def _short(value: object) -> str:
    return repr(value)[:40]


def _validate_marker(probe: Probe) -> None:
    marker = probe.marker
    if marker is None:
        if probe.detector == "marker_echo":
            raise _invalid(f"probe {probe.id}: marker_echo requires a marker")
        return
    if not isinstance(marker, str) or len(marker) > MAX_MARKER_CHARS:
        raise _invalid(f"probe {probe.id}: marker must be a string of at most 200 characters")
    if probe.detector == "marker_echo" and not normalize(marker):
        raise _invalid(f"probe {probe.id}: marker is empty after normalisation")


def validate_probe(probe: Probe) -> None:
    """Raise ``RedteamError`` (``catalog_invalid``) if ``probe`` is malformed."""
    if not isinstance(probe.id, str) or not _ID_RE.fullmatch(probe.id):
        raise _invalid("probe id must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
    checks = (
        ("category", probe.category, CATEGORIES),
        ("severity", probe.severity, SEVERITIES),
        ("owasp", probe.owasp, OWASP_IDS),
        ("detector", probe.detector, DETECTORS),
    )
    for name, value, allowed in checks:
        if value not in allowed:
            raise _invalid(f"probe {probe.id}: {name} {_short(value)} is not allowed")
    if not isinstance(probe.prompt, str) or not probe.prompt.strip():
        raise _invalid(f"probe {probe.id}: prompt must be a non-empty string")
    if len(probe.prompt) > MAX_PROMPT_CHARS:
        raise _invalid(f"probe {probe.id}: prompt exceeds {MAX_PROMPT_CHARS} characters")
    _validate_marker(probe)


def _parse_probe(raw: object, index: int) -> Probe:
    if not isinstance(raw, dict):
        raise _invalid(f"probe #{index} must be an object")
    keys = set(raw)
    if not keys >= _REQUIRED_FIELDS or not keys <= _ALLOWED_FIELDS:
        raise _invalid(f"probe #{index} has missing or unknown fields")
    probe = Probe(
        id=raw["id"],
        category=raw["category"],
        severity=raw["severity"],
        owasp=raw["owasp"],
        prompt=raw["prompt"],
        detector=raw["detector"],
        marker=raw.get("marker"),
    )
    validate_probe(probe)
    return probe


def parse_catalog(data: bytes) -> list[Probe]:
    """Parse and validate catalog JSON bytes (at most 1 MiB, 1000 probes)."""
    if len(data) > MAX_CATALOG_BYTES:
        raise _invalid("catalog exceeds the 1 MiB limit")
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise _invalid("catalog is not valid UTF-8 JSON") from exc
    if isinstance(document, dict):
        version = document.get("version")
        if version is not None and not isinstance(version, str):
            raise _invalid("catalog version must be a string")
        items = document.get("probes")
    else:
        items = document
    if not isinstance(items, list):
        raise _invalid("catalog must contain a list of probes")
    if len(items) > MAX_PROBES:
        raise _invalid(f"catalog has more than {MAX_PROBES} probes")
    probes = [_parse_probe(item, index) for index, item in enumerate(items)]
    seen: set[str] = set()
    for probe in probes:
        if probe.id in seen:
            raise _invalid(f"duplicate probe id {probe.id}")
        seen.add(probe.id)
    return probes


def load_probes(path: Path | None = None) -> list[Probe]:
    """Load the bundled catalog (``path=None``) or a custom JSON catalog file.

    Custom files are limited to 1 MiB and 1000 probes.

    Raises:
        RedteamError: ``catalog_invalid`` if the catalog cannot be read or is malformed.
    """
    if path is None:
        resource = importlib.resources.files("redteam_suite").joinpath("probes.json")
        return parse_catalog(resource.read_bytes())
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_CATALOG_BYTES + 1)
    except OSError as exc:
        raise _invalid(f"cannot read catalog file: {type(exc).__name__}") from exc
    return parse_catalog(data)


def select_probes(
    probes: Iterable[Probe],
    categories: Iterable[str] = (),
    ids: Iterable[str] = (),
) -> list[Probe]:
    """Filter ``probes`` by category and id, keeping catalog order.

    Raises:
        RedteamError: ``unknown_category`` or ``unknown_probe`` for unknown filter values.
    """
    catalog = list(probes)
    wanted_categories = set(categories)
    wanted_ids = set(ids)
    for category in sorted(wanted_categories):
        if category not in CATEGORIES:
            raise RedteamError("unknown_category", f"unknown category {category[:40]!r}")
    known = {probe.id for probe in catalog}
    for probe_id in sorted(wanted_ids):
        if probe_id not in known:
            raise RedteamError("unknown_probe", f"unknown probe id {probe_id[:40]!r}")
    selected: list[Probe] = []
    for probe in catalog:
        if wanted_categories and probe.category not in wanted_categories:
            continue
        if wanted_ids and probe.id not in wanted_ids:
            continue
        selected.append(probe)
    return selected
