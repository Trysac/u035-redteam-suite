"""Typed errors for redteam_suite."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal[
    "catalog_invalid",
    "unknown_probe",
    "unknown_category",
    "remote_target_refused",
    "unsupported_scheme",
    "redirect_refused",
    "response_too_large",
]

MAX_MESSAGE_CHARS = 200


class RedteamError(Exception):
    """Base error of the library; ``code`` is a stable machine-readable identifier."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message[:MAX_MESSAGE_CHARS])
        self.code: ErrorCode = code
