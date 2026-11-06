"""Suite runner, result model and report."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass

from .detectors import check_canary, detect
from .errors import RedteamError
from .probes import MAX_PROBES, Category, Owasp, Probe, Severity, validate_probe
from .targets import Target

logger = logging.getLogger(__name__)

MAX_EXCERPT_CHARS = 2000
MAX_RESPONSE_CHARS = 4_194_304

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_BLOCKING = frozenset({"critical", "high"})


@dataclass(frozen=True)
class ProbeEvent:
    """Progress notification for one probe; carries no prompt or response text."""

    probe_id: str
    succeeded: bool
    latency_ms: float
    error_type: str | None


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one probe; ``succeeded`` means the attack worked against the target."""

    probe_id: str
    category: Category
    severity: Severity
    owasp: Owasp
    succeeded: bool
    latency_ms: float
    response_excerpt: str
    error: str | None


@dataclass(frozen=True)
class SuiteReport:
    """Results ordered by severity (critical first) and then probe id."""

    results: tuple[ProbeResult, ...]

    @property
    def succeeded_count(self) -> int:
        """Number of probes that succeeded against the target."""
        return sum(1 for item in self.results if item.succeeded)

    @property
    def has_blocking_success(self) -> bool:
        """True if any ``high`` or ``critical`` probe succeeded."""
        return any(item.succeeded and item.severity in _BLOCKING for item in self.results)

    def to_json(self) -> str:
        """Serialise the report as JSON text."""
        payload: dict[str, object] = {
            "total": len(self.results),
            "succeeded": self.succeeded_count,
            "results": [asdict(item) for item in self.results],
        }
        return json.dumps(payload, indent=2)


def _validate_selection(probes: Sequence[Probe]) -> None:
    if len(probes) > MAX_PROBES:
        raise RedteamError("catalog_invalid", f"at most {MAX_PROBES} probes can be run")
    seen: set[str] = set()
    for probe in probes:
        validate_probe(probe)
        if probe.id in seen:
            raise RedteamError("catalog_invalid", f"duplicate probe id {probe.id}")
        seen.add(probe.id)


def _run_one(
    target: Target,
    probe: Probe,
    canary: str,
    clock: Callable[[], float],
) -> tuple[ProbeResult, ProbeEvent]:
    started = clock()
    response = ""
    error: str | None = None
    error_type: str | None = None
    try:
        raw = target.send(probe.prompt)
        if not isinstance(raw, str):
            raise TypeError("target returned a non-string response")
        if len(raw) > MAX_RESPONSE_CHARS:
            raise RedteamError("response_too_large", "response exceeds the character limit")
        response = raw
    except Exception as exc:
        error_type = type(exc).__name__
        error = f"{error_type}: {str(exc)[:200]}"
    finished = clock()
    latency_ms = round(max(0.0, finished - started) * 1000.0, 3)
    succeeded = False
    if error is None:
        succeeded = detect(probe.detector, response, canary=canary, marker=probe.marker)
    result = ProbeResult(
        probe_id=probe.id,
        category=probe.category,
        severity=probe.severity,
        owasp=probe.owasp,
        succeeded=succeeded,
        latency_ms=latency_ms,
        response_excerpt=response[:MAX_EXCERPT_CHARS],
        error=error,
    )
    event = ProbeEvent(probe.id, succeeded, latency_ms, error_type)
    return result, event


def _notify(on_event: Callable[[ProbeEvent], None] | None, event: ProbeEvent) -> None:
    if on_event is None:
        return
    try:
        on_event(event)
    except Exception as exc:
        logger.warning("on_event callback failed: %s", type(exc).__name__)


def run_suite(
    target: Target,
    probes: Sequence[Probe],
    canary: str,
    clock: Callable[[], float] = time.monotonic,
    on_event: Callable[[ProbeEvent], None] | None = None,
) -> SuiteReport:
    """Send every probe to ``target`` once, in order, and score the answers.

    A target exception is recorded on the result and the run continues. ``clock`` is called
    exactly twice per probe.

    Raises:
        ValueError: if ``canary`` is shorter than 12 characters or longer than 512.
        RedteamError: ``catalog_invalid`` for malformed or duplicate probes, or too many.
    """
    check_canary(canary)
    _validate_selection(probes)
    results: list[ProbeResult] = []
    for probe in probes:
        result, event = _run_one(target, probe, canary, clock)
        logger.debug("probe %s finished (succeeded=%s)", probe.id, result.succeeded)
        results.append(result)
        _notify(on_event, event)
    ordered = sorted(results, key=lambda item: (_SEVERITY_RANK[item.severity], item.probe_id))
    return SuiteReport(results=tuple(ordered))
