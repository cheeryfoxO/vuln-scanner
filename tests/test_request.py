"""Tests for HTTP request wrapper."""
from scanner.core.request import RequestHandler, USER_AGENTS


def test_default_timeout_is_10():
    rh = RequestHandler()
    assert rh.timeout == 10


def test_custom_timeout():
    rh = RequestHandler(timeout=5)
    assert rh.timeout == 5


def test_user_agents_non_empty():
    assert len(USER_AGENTS) >= 3
    for ua in USER_AGENTS:
        assert isinstance(ua, str)
        assert len(ua) > 20


def test_session_created():
    rh = RequestHandler()
    assert rh.session is not None


class TestPost:
    def test_post_method_exists(self):
        rh = RequestHandler()
        assert hasattr(rh, "post")
        assert callable(rh.post)

    def test_post_accepts_data(self):
        rh = RequestHandler()
        import inspect
        sig = inspect.signature(rh.post)
        params = list(sig.parameters.keys())
        assert "url" in params
        assert "data" in params


class TestDelay:
    def test_default_delay_is_zero(self):
        rh = RequestHandler()
        assert rh.delay == 0

    def test_custom_delay_converts_ms_to_seconds(self):
        rh = RequestHandler(delay=200)
        assert rh.delay == 0.2


class TestCookies:
    def test_cookie_string_parsed(self):
        rh = RequestHandler(cookies="session=abc; token=xyz")
        cookies = rh.session.cookies.get_dict()
        assert cookies.get("session") == "abc"
        assert cookies.get("token") == "xyz"

    def test_no_cookies_by_default(self):
        rh = RequestHandler()
        assert rh.session.cookies.get_dict() == {}


class TestExtraHeaders:
    def test_extra_headers_stored(self):
        rh = RequestHandler(extra_headers={"X-Custom": "val"})
        assert rh.extra_headers == {"X-Custom": "val"}

    def test_no_extra_headers_by_default(self):
        rh = RequestHandler()
        assert rh.extra_headers == {}
