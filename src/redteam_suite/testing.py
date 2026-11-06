"""Test doubles for ``Target``."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping

MAX_RECORDED_CALLS = 1000
DEFAULT_RESPONSE = "I can't help with that."


class FakeTarget:
    """A deterministic target that answers from a prompt-to-response mapping.

    Unknown prompts get ``default``. The most recent ``MAX_RECORDED_CALLS`` prompts are kept.
    """

    def __init__(self, responses: Mapping[str, str], default: str = DEFAULT_RESPONSE) -> None:
        self._responses = dict(responses)
        self._default = default
        self._calls: deque[str] = deque(maxlen=MAX_RECORDED_CALLS)

    def send(self, prompt: str) -> str:
        """Record ``prompt`` and return the configured answer."""
        self._calls.append(prompt)
        return self._responses.get(prompt, self._default)

    @property
    def calls(self) -> tuple[str, ...]:
        """Prompts received so far, oldest first."""
        return tuple(self._calls)
