"""Target adapters: the ``Target`` protocol and the loopback-first ``HttpTarget``."""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.request
from collections.abc import Mapping
from http.client import HTTPMessage
from typing import IO, NoReturn, Protocol
from urllib.parse import urlsplit

from .errors import RedteamError

MAX_URL_CHARS = 2048
MAX_HEADERS = 50
MAX_HEADER_VALUE_CHARS = 8192

_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")


class Target(Protocol):
    """Anything that can answer a prompt with text."""

    def send(self, prompt: str) -> str:
        """Send ``prompt`` to the system under test and return its answer."""
        ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect so a target cannot bounce the request elsewhere."""

    def http_error_302(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
    ) -> NoReturn:
        fp.close()
        raise RedteamError("redirect_refused", f"the target answered with HTTP {code}")


for _status in (301, 303, 307, 308):
    setattr(_NoRedirectHandler, f"http_error_{_status}", _NoRedirectHandler.http_error_302)


def _is_local_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if str(address) != host:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return False
    return address.is_loopback


def _check_url(url: str, allow_remote: bool) -> None:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
        raise RedteamError("remote_target_refused", "the target URL is missing or too long")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port
    except ValueError as exc:
        raise RedteamError("remote_target_refused", "the target URL is invalid") from exc
    if parts.scheme not in ("http", "https"):
        raise RedteamError("unsupported_scheme", f"scheme {parts.scheme[:20]!r} is not supported")
    if host is None:
        raise RedteamError("remote_target_refused", "the target URL has no host")
    if not allow_remote and not _is_local_host(host):
        raise RedteamError("remote_target_refused", "only loopback hosts are allowed by default")


def _header_value_ok(value: str) -> bool:
    if len(value) > MAX_HEADER_VALUE_CHARS or any(ch in value for ch in "\r\n\x00"):
        return False
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        return False
    return True


def _validate_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if headers is None:
        return {}
    if len(headers) > MAX_HEADERS:
        raise ValueError("too many HTTP headers")
    checked: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            raise ValueError("invalid HTTP header name")
        if not isinstance(value, str) or not _header_value_ok(value):
            raise ValueError(f"invalid value for HTTP header {name[:50]}")
        checked[name] = value
    return checked


class HttpTarget:
    """POST each prompt as JSON to an HTTP endpoint you own.

    Without ``allow_remote`` only ``localhost`` and canonical loopback IP literals are accepted.
    Redirects are refused, proxies are not used and responses are capped at
    ``max_response_bytes``. Header values are never logged, stored in errors or repr'd.
    """

    def __init__(
        self,
        url: str,
        field: str = "prompt",
        response_field: str = "output",
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
        allow_remote: bool = False,
        max_response_bytes: int = 1_048_576,
    ) -> None:
        _check_url(url, allow_remote)
        if not field or not response_field:
            raise ValueError("field and response_field must be non-empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be at least 1")
        merged = {"Content-Type": "application/json"}
        merged.update(_validate_headers(headers))
        self._url = url
        self._field = field
        self._response_field = response_field
        self._headers = merged
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
        )

    def send(self, prompt: str) -> str:
        """POST ``prompt`` and return the text answer.

        Raises:
            RedteamError: ``redirect_refused`` or ``response_too_large``.
            ValueError: if the reply is not JSON with a string ``response_field``.
        """
        body = json.dumps({self._field: prompt}).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310, RUF100
            self._url,
            data=body,
            headers=self._headers,
            method="POST",
        )
        with self._opener.open(request, timeout=self._timeout) as response:
            raw = response.read(self._max_response_bytes + 1)
            content_type = str(response.headers.get("Content-Type", ""))
        if len(raw) > self._max_response_bytes:
            raise RedteamError("response_too_large", "the response exceeds max_response_bytes")
        return self._extract(raw, content_type.split(";")[0].strip().lower())

    def _extract(self, raw: bytes, content_type: str) -> str:
        text = raw.decode("utf-8", errors="replace")
        if content_type == "text/plain":
            return text
        try:
            document = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise ValueError("the response is not valid JSON") from exc
        value = document.get(self._response_field) if isinstance(document, dict) else None
        if not isinstance(value, str):
            raise ValueError(f"the response lacks a string field {self._response_field[:50]!r}")
        return value
