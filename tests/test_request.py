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
