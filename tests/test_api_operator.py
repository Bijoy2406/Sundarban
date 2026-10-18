"""Separation of duties: the person who confirms an action or switches the kill switch OFF holds an operator key
(env OPERATOR_TOKEN, header X-Operator-Token). Switching the kill switch ON stays open: freezing must be easy.
Fail closed: with no usable OPERATOR_TOKEN both protected actions answer 503, never 'allowed'."""
import pytest
from fastapi.testclient import TestClient

import api.main as api
from firewall import state
from shared.redact import redact
from tests.operator_key import OPERATOR_TOKEN, operator_headers

client = TestClient(api.app)
CONFIRM = {"request_id": "not-pending"}                 # a valid body for an unknown request: 404 once the gate is passed
WRONG = "wrong-operator-key-0123456789abcdef"
UNCONFIGURED = "Operator protection is not configured: set OPERATOR_TOKEN in .env"
REFUSED = "Operator key missing or wrong"


def _post_confirm(**kwargs):
    return client.post("/api/confirm", json=CONFIRM, **kwargs)


# ------------------------------------------------------------------ /api/confirm

def test_confirm_without_the_key_is_refused():
    response = _post_confirm()
    assert response.status_code == 403 and response.json()["detail"] == REFUSED


def test_confirm_with_a_wrong_key_is_refused_with_the_same_text():
    missing, wrong = _post_confirm(), _post_confirm(headers=operator_headers(WRONG))
    assert wrong.status_code == 403 and wrong.json() == missing.json()          # nothing tells the two cases apart


def test_confirm_with_the_right_key_gets_past_the_gate():
    assert _post_confirm(headers=operator_headers()).status_code == 404          # "missing, expired or already used"


@pytest.mark.parametrize("configured", ["", "short", "x" * 15])
def test_confirm_fails_closed_when_the_token_is_unset_or_too_short(monkeypatch, configured):
    monkeypatch.setenv("OPERATOR_TOKEN", configured)
    for headers in ({}, operator_headers(configured or "anything"), operator_headers()):
        response = _post_confirm(headers=headers)
        assert response.status_code == 503 and response.json()["detail"] == UNCONFIGURED


def test_confirm_fails_closed_when_the_variable_does_not_exist(monkeypatch):
    monkeypatch.delenv("OPERATOR_TOKEN", raising=False)
    assert _post_confirm(headers=operator_headers()).status_code == 503


def test_a_sixteen_character_token_is_enough(monkeypatch):
    monkeypatch.setenv("OPERATOR_TOKEN", "a" * 16)
    assert _post_confirm(headers=operator_headers("a" * 16)).status_code == 404


def test_the_key_comparison_is_exact(monkeypatch):
    for variant in (OPERATOR_TOKEN.upper(), OPERATOR_TOKEN + " ", " " + OPERATOR_TOKEN, OPERATOR_TOKEN[:-1], OPERATOR_TOKEN + "x"):
        assert _post_confirm(headers=operator_headers(variant)).status_code == 403, repr(variant)


# ------------------------------------------------------------------ /api/kill-switch

def test_switching_the_kill_switch_on_needs_no_key():
    response = client.post("/api/kill-switch", json={"enabled": True})
    assert response.status_code == 200 and response.json()["kill_switch_on"] is True
    assert state.kill_switch_on() is True


@pytest.mark.parametrize("headers", [{}, operator_headers(WRONG)])
def test_switching_it_off_without_the_right_key_is_refused_and_it_stays_on(headers):
    state.set_kill_switch(True)
    response = client.post("/api/kill-switch", json={"enabled": False}, headers=headers)
    assert response.status_code == 403 and response.json()["detail"] == REFUSED
    assert state.kill_switch_on() is True


def test_switching_it_off_with_the_right_key_works():
    state.set_kill_switch(True)
    response = client.post("/api/kill-switch", json={"enabled": False}, headers=operator_headers())
    assert response.status_code == 200 and response.json()["kill_switch_on"] is False
    assert state.kill_switch_on() is False


def test_off_fails_closed_without_a_configured_token_but_on_still_works(monkeypatch):
    monkeypatch.delenv("OPERATOR_TOKEN", raising=False)
    state.set_kill_switch(True)
    off = client.post("/api/kill-switch", json={"enabled": False}, headers=operator_headers())
    assert off.status_code == 503 and off.json()["detail"] == UNCONFIGURED and state.kill_switch_on() is True
    assert client.post("/api/kill-switch", json={"enabled": True}).status_code == 200      # freezing is never blocked


# ------------------------------------------------------------------ the key itself is never exposed

def test_no_response_contains_the_token_or_the_value_that_was_sent():
    responses = [
        _post_confirm(), _post_confirm(headers=operator_headers(WRONG)), _post_confirm(headers=operator_headers()),
        client.post("/api/kill-switch", json={"enabled": False}),
        client.post("/api/kill-switch", json={"enabled": False}, headers=operator_headers(WRONG)),
        client.get("/api/health"), client.get("/api/security"), client.get("/api/llm/status"),
    ]
    for response in responses:
        assert OPERATOR_TOKEN not in response.text and WRONG not in response.text


def test_redact_hides_the_operator_token_wherever_it_appears():
    assert OPERATOR_TOKEN not in redact(f"request failed with header X-Operator-Token: {OPERATOR_TOKEN} sent")
    assert "[hidden]" in redact(f"token {OPERATOR_TOKEN}")


def test_the_gate_does_not_log_the_token(caplog):
    with caplog.at_level("DEBUG"):
        _post_confirm(headers=operator_headers(WRONG))
        _post_confirm(headers=operator_headers())
    assert OPERATOR_TOKEN not in caplog.text and WRONG not in caplog.text
