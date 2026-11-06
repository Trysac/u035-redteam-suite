from __future__ import annotations

import email.message
import io
import json
import urllib.request
import urllib.response

import pytest

from redteam_suite.errors import RedteamError
from redteam_suite.targets import HttpTarget

AUTH_VALUE = "Bearer test-credential-value"

ACCEPTED = [
    "http://127.0.0.1:8080/x",
    "http://[::1]/x",
    "http://localhost/x",
]
REFUSED_BY_DEFAULT = [
    "http://127.0.0.1.example.com/",
    "http://localhost.example.com/",
    "http://[::ffff:127.0.0.1]/",
    "http://0x7f.1/",
]
ALWAYS_REFUSED = [
    "http://example.com/x",
    "http://10.0.0.1/",
    "http://127.1/",
    "http://localhost./",
    "http://[::ffff:7f00:1]/",
    "http://localhost:99999/",
]


class _FakeResponse:
    def __init__(self, body: bytes, content_type: str | None = "application/json") -> None:
        self._body = body
        self.headers: dict[str, str] = {}
        if content_type is not None:
            self.headers["Content-Type"] = content_type
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self._body if size < 0 else self._body[:size]

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _FakeOpener:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.requests: list[urllib.request.Request] = []
        self.timeouts: list[float] = []

    def open(self, request: urllib.request.Request, timeout: float) -> _FakeResponse:
        self.requests.append(request)
        self.timeouts.append(timeout)
        return self.response


class _StatusHandler(urllib.request.BaseHandler):
    handler_order = 100

    def __init__(self, code: int) -> None:
        self._code = code

    def http_open(self, req: urllib.request.Request) -> urllib.response.addinfourl:
        response = urllib.response.addinfourl(
            io.BytesIO(b""),
            email.message.Message(),
            req.full_url,
            self._code,
        )
        response.msg = "Found"
        return response


def _target(response: _FakeResponse, **kwargs: object) -> tuple[HttpTarget, _FakeOpener]:
    target = HttpTarget("http://localhost/x", **kwargs)  # type: ignore[arg-type]
    opener = _FakeOpener(response)
    target._opener = opener  # type: ignore[assignment]
    return target, opener


@pytest.mark.parametrize("url", ACCEPTED)
def test_loopback_urls_are_accepted(url: str) -> None:
    HttpTarget(url)


@pytest.mark.parametrize("url", REFUSED_BY_DEFAULT + ALWAYS_REFUSED)
def test_non_loopback_urls_are_refused_by_default(url: str) -> None:
    with pytest.raises(RedteamError) as info:
        HttpTarget(url)
    assert info.value.code == "remote_target_refused"


@pytest.mark.parametrize("url", REFUSED_BY_DEFAULT)
def test_allow_remote_opens_other_hosts(url: str) -> None:
    HttpTarget(url, allow_remote=True)


@pytest.mark.parametrize("allow_remote", [False, True])
@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://localhost/x", "localhost/x"])
def test_unsupported_scheme(url: str, allow_remote: bool) -> None:
    with pytest.raises(RedteamError) as info:
        HttpTarget(url, allow_remote=allow_remote)
    assert info.value.code == "unsupported_scheme"


def test_url_without_host_or_too_long_is_refused() -> None:
    for url in ("http:///x", "", "http://localhost/" + "a" * 3000):
        with pytest.raises(RedteamError) as info:
            HttpTarget(url, allow_remote=True)
        assert info.value.code == "remote_target_refused"


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_refused(status: int) -> None:
    target = HttpTarget("http://localhost/x")
    target._opener.add_handler(_StatusHandler(status))
    with pytest.raises(RedteamError) as info:
        target.send("hi")
    assert info.value.code == "redirect_refused"


def test_constructor_argument_validation() -> None:
    url = "http://localhost/x"
    with pytest.raises(ValueError, match="non-empty"):
        HttpTarget(url, field="")
    with pytest.raises(ValueError, match="non-empty"):
        HttpTarget(url, response_field="")
    with pytest.raises(ValueError, match="timeout"):
        HttpTarget(url, timeout=0)
    with pytest.raises(ValueError, match="max_response_bytes"):
        HttpTarget(url, max_response_bytes=0)


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Test": "a\r\nInjected: yes"},
        {"X-Test": "nul\x00"},
        {"X-Test": "caf\u00e9\u20ac"},
        {"X-Test": "v" * 9000},
        {"Bad Name": "v"},
        {"": "v"},
        {f"X-{i}": "v" for i in range(51)},
    ],
)
def test_invalid_headers_are_rejected_without_echoing_values(headers: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="HTTP header") as info:
        HttpTarget("http://localhost/x", headers=headers)
    assert "Injected" not in str(info.value)


def test_send_posts_json_with_headers_and_timeout() -> None:
    response = _FakeResponse(b'{"output": "hello"}')
    target, opener = _target(response, headers={"Authorization": AUTH_VALUE}, timeout=5.0)
    assert target.send("hi") == "hello"
    request = opener.requests[0]
    assert request.data == b'{"prompt": "hi"}'
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == AUTH_VALUE
    assert request.get_header("Content-type") == "application/json"
    assert opener.timeouts == [5.0]
    assert AUTH_VALUE not in repr(target)


def test_custom_field_names() -> None:
    body = json.dumps({"reply": "ok"}).encode()
    target, opener = _target(_FakeResponse(body), field="q", response_field="reply")
    assert target.send("hi") == "ok"
    assert opener.requests[0].data == b'{"q": "hi"}'


def test_text_plain_body_is_returned_whole() -> None:
    target, _ = _target(_FakeResponse(b"plain answer", "text/plain; charset=utf-8"))
    assert target.send("hi") == "plain answer"


def test_missing_content_type_is_treated_as_json() -> None:
    target, _ = _target(_FakeResponse(b'{"output": "x"}', None))
    assert target.send("hi") == "x"


def test_response_of_max_bytes_is_accepted_and_one_more_is_refused() -> None:
    ok = _FakeResponse(b"x" * 10, "text/plain")
    target, _ = _target(ok, max_response_bytes=10)
    assert target.send("hi") == "x" * 10
    too_big = _FakeResponse(b"x" * 11, "text/plain")
    target, _ = _target(too_big, max_response_bytes=10)
    with pytest.raises(RedteamError) as info:
        target.send("hi")
    assert info.value.code == "response_too_large"
    assert too_big.read_sizes == [11]


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[1, 2]", b'{"other": "x"}', b'{"output": 5}', b"[" * 100_000],
)
def test_unusable_json_reply_raises_value_error(body: bytes) -> None:
    target, _ = _target(_FakeResponse(body))
    with pytest.raises(ValueError, match="response"):
        target.send("hi")
