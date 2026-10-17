"""Tests for the local-only side-by-side attack replay API."""
from types import SimpleNamespace

from fastapi.testclient import TestClient

import api.main as api
from shared.types import AgentReply, Decision


client = TestClient(api.app)


def _local_chain(monkeypatch):
    monkeypatch.setattr(api.chain, "network", lambda: "local")
    monkeypatch.setattr(api.chain, "get_web3", lambda: SimpleNamespace(
        is_connected=lambda: True, eth=SimpleNamespace(chain_id=31337)
    ))
    monkeypatch.setattr(api.drainer, "attacker_address", lambda: "0x" + "ab" * 20)


def test_feed_endpoint_returns_synthetic_items():
    response = client.get("/api/feed")
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 9
    assert sum(item["attack"] for item in items) == 6
    assert all(item["origin"] in {"public_feed", "nft_metadata"} for item in items)


def test_attack_replay_runs_both_sides_and_reports_balance_drop(monkeypatch):
    _local_chain(monkeypatch)
    calls = []
    monkeypatch.setattr(api, "protected_handle_message", lambda text, origin: (
        calls.append(("protected", text, origin)) or AgentReply(
            text="Denied by firewall.", decision=Decision("p1", "deny", ["PRV-01"], ["Untrusted public feed"]), blocked=True
        )
    ))
    monkeypatch.setattr(api.naive_agent, "handle_message", lambda text, origin: (
        calls.append(("naive", text, origin)) or AgentReply(
            text="Naive agent approved the malicious allowance.",
            decision=Decision("n1", "allow"), tx_hash="0xapproval", blocked=False
        )
    ))
    monkeypatch.setattr(api.drainer, "drain", lambda: SimpleNamespace(
        tx_hash="0xdrain", victim_before="1000", victim_after="0", amount="1000"
    ))

    response = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"})
    assert response.status_code == 200
    body = response.json()
    assert body["naive"]["tx_hash"] == "0xapproval"
    assert body["naive"]["drain_tx_hash"] == "0xdrain"
    assert body["naive"]["balance_before"] == "1000"
    assert body["naive"]["balance_after"] == "0"
    assert body["naive"]["balance_drop"] == "1000"
    assert body["protected"]["status"] == "blocked"
    assert body["protected"]["decision"]["decision"] == "deny"
    assert [call[0] for call in calls] == ["protected", "naive"]
    assert all(call[2] == "public_feed" for call in calls)
    assert "0x" + "ab" * 20 in calls[0][1]
    assert "0x" + "ab" * 20 in calls[1][1]


def test_attack_replay_rejects_benign_item(monkeypatch):
    _local_chain(monkeypatch)
    response = client.post("/api/attack-replay", json={"attack_id": "x-benign-1"})
    assert response.status_code == 400
    assert "attack item" in response.json()["detail"]


def test_attack_replay_rejects_unknown_item(monkeypatch):
    _local_chain(monkeypatch)
    response = client.post("/api/attack-replay", json={"attack_id": "not-real"})
    assert response.status_code == 404


def test_attack_replay_refuses_non_local_network(monkeypatch):
    monkeypatch.setattr(api.chain, "network", lambda: "sepolia")
    response = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"})
    assert response.status_code == 403
