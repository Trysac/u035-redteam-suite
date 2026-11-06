"""Run benign adversarial probes against an LLM target you own and report findings."""

from __future__ import annotations

import logging

from .errors import RedteamError
from .probes import Probe, load_probes, select_probes
from .runner import ProbeEvent, ProbeResult, SuiteReport, run_suite
from .targets import HttpTarget, Target

__all__ = [
    "HttpTarget",
    "Probe",
    "ProbeEvent",
    "ProbeResult",
    "RedteamError",
    "SuiteReport",
    "Target",
    "__version__",
    "load_probes",
    "run_suite",
    "select_probes",
]

__version__ = "0.1.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())
