from __future__ import annotations

import logging

import redteam_suite


def test_public_api_is_exported() -> None:
    for name in redteam_suite.__all__:
        assert hasattr(redteam_suite, name)


def test_version() -> None:
    assert redteam_suite.__version__ == "0.1.0"


def test_null_handler_is_installed() -> None:
    handlers = logging.getLogger("redteam_suite").handlers
    assert any(isinstance(handler, logging.NullHandler) for handler in handlers)


def test_error_code_and_message_cap() -> None:
    error = redteam_suite.RedteamError("unknown_probe", "x" * 500)
    assert error.code == "unknown_probe"
    assert len(str(error)) == 200
