"""Tests for firewall/provenance.py (issue #14): only user_chat is trusted (PRV-01)."""
import pytest

from firewall import provenance
from shared.types import ActionRequest

UNTRUSTED = ["public_feed", "nft_metadata", "tool_output"]


def _req(origin):
    return ActionRequest("r1", "transfer", "0xTOKEN", "0xALICE", "10", False, origin)


def test_user_chat_is_trusted():
    assert provenance.is_trusted("user_chat") is True
    assert provenance.check(_req("user_chat")) is None


@pytest.mark.parametrize("origin", UNTRUSTED)
def test_each_untrusted_origin_is_denied_with_prv01(origin):
    assert provenance.is_trusted(origin) is False
    hit = provenance.check(_req(origin))
    assert hit is not None
    rule_id, reason = hit
    assert rule_id == "PRV-01"
    assert origin in reason


@pytest.mark.parametrize("origin", ["", "  ", "USER_CHAT", " user_chat", "user_chat ", "user_chat2",
                                    "admin", "system", None, 5, ["user_chat"]])
def test_odd_or_unknown_origins_are_not_trusted(origin):
    assert provenance.is_trusted(origin) is False
    assert provenance.check(_req(origin))[0] == "PRV-01"


def test_cannot_read_rules_means_nobody_is_trusted(monkeypatch, tmp_path):
    monkeypatch.setenv("RULES_PATH", str(tmp_path / "does_not_exist.yaml"))
    assert provenance.is_trusted("user_chat") is False


def test_trust_comes_from_rules_yaml(monkeypatch, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text('auto_limit: "50"\nmax_tx: "500"\ndaily_cap: "1000"\n'
                     "velocity:\n  max_actions: 5\n  window_seconds: 600\n"
                     "trusted_origins: [user_chat, ui_button]\n")
    monkeypatch.setenv("RULES_PATH", str(rules))
    assert provenance.is_trusted("ui_button") is True
    assert provenance.is_trusted("public_feed") is False