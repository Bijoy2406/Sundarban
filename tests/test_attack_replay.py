"""The local-only attack replay (agent/replay.py + /api/attack-replay).

Offline tests use fakes for the model, the two agents and the drainer. The live test at the bottom runs the whole
replay on a real local Anvil (skipped without one).
"""
import os
from decimal import Decimal
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import api.main as api
from agent import replay
from agent.feed import get_feed_item, get_feed_items
from agent.intents import IntentParseError
from shared.types import AgentReply, Decision

client = TestClient(api.app)
ATTACKER = "0x" + "ab" * 20
ATTACKS = [item.id for item in get_feed_items() if item.attack]


def fooled_model(item_intent):
    """A fake model that does what the attack text says (it is fooled)."""
    return lambda text, **kwargs: dict(item_intent)


def approve_intent(to=ATTACKER):
    return {"action": "approve", "token": "TUSD", "to": to, "amount": "0", "unlimited": True, "rationale": "x"}


def transfer_intent(to=ATTACKER, amount="10"):
    return {"action": "transfer", "token": "TUSD", "to": to, "amount": amount, "unlimited": False, "rationale": "x"}


@pytest.fixture
def world(monkeypatch):
    """A fake local chain, fake agents and a fake drainer; records what each side was given."""
    calls = {"protected": [], "naive": [], "drain": 0, "chain": []}
    state = {"balance": Decimal("1000"), "allowance": False}
    saved = {}

    def make_request(method, params):
        """A fake Anvil: evm_snapshot remembers the state, evm_revert really restores it."""
        calls["chain"].append(method)
        if method == "evm_snapshot":
            saved["0x1"] = dict(state)
            return {"result": "0x1"}
        if method == "evm_revert":
            state.update(saved[params[0]])
            return {"result": True}
        raise AssertionError(method)
    monkeypatch.setattr(replay.chain, "network", lambda: "local")
    monkeypatch.setattr(replay.chain, "get_web3", lambda: SimpleNamespace(
        is_connected=lambda: True, eth=SimpleNamespace(chain_id=31337), provider=SimpleNamespace(make_request=make_request)))
    monkeypatch.setattr(replay.drainer, "attacker_address", lambda: ATTACKER)
    monkeypatch.setattr(replay, "_victim_balance", lambda: state["balance"])
    monkeypatch.setattr(replay, "_attacker_has_allowance", lambda attacker: state["allowance"])
    monkeypatch.setattr(replay, "parse_intent", fooled_model(approve_intent()))

    def protected(intent, origin):
        calls["protected"].append((intent, origin))
        return AgentReply(text="I can't execute this request because the wallet firewall denied it.",
                          decision=Decision("p1", "deny", ["PRV-01", "APR-01"], ["Untrusted source", "Unlimited approval"]),
                          blocked=True)

    def naive(intent, origin):
        calls["naive"].append((intent, origin))
        if intent["action"] == "approve":
            state["allowance"] = True
        else:
            state["balance"] -= Decimal(intent["amount"])
        return AgentReply(text="Naive agent executed the LLM-extracted request.", decision=Decision("n1", "allow"),
                          tx_hash="0xnaive", blocked=False)

    def drain():
        calls["drain"] += 1
        before, state["balance"] = state["balance"], Decimal(0)
        return SimpleNamespace(tx_hash="0xdrain", victim_before=format(before, "f"), victim_after="0", amount=format(before, "f"))
    monkeypatch.setattr(replay.protected, "handle_intent", protected)
    monkeypatch.setattr(replay.naive_agent, "handle_intent", naive)
    monkeypatch.setattr(replay.drainer, "drain", drain)
    return SimpleNamespace(calls=calls, state=state)


# ------------------------------------------------------------------ the chain is rolled back after every replay

def test_the_chain_is_snapshotted_first_and_reverted_last(world):
    body = replay.run(get_feed_item("x-attack-direct"))
    assert world.calls["chain"] == ["evm_snapshot", "evm_revert"]
    assert body["chain_reset"] is True
    assert world.state["balance"] == Decimal("1000") and world.state["allowance"] is False     # the replay left nothing behind


def test_the_result_is_built_before_the_revert_so_it_still_shows_the_loss(world):
    body = replay.run(get_feed_item("x-attack-direct"))
    assert body["naive"]["status"] == "drained" and Decimal(body["naive"]["balance_drop"]) == Decimal("1000")
    assert body["naive"]["balance_before"] == "1000" and body["naive"]["balance_after"] == "0"


def test_two_replays_in_a_row_give_the_same_naive_result(world):
    first = replay.run(get_feed_item("x-attack-direct"))
    second = replay.run(get_feed_item("x-attack-direct"))
    assert first["naive"] == second["naive"] and first["naive"]["status"] == "drained"


@pytest.mark.parametrize("side", ["protected", "naive"])
def test_the_revert_runs_even_when_an_agent_raises(world, monkeypatch, side):
    def boom(intent, origin):
        raise RuntimeError("agent crashed")
    monkeypatch.setattr(getattr(replay, "protected" if side == "protected" else "naive_agent"), "handle_intent", boom)
    with pytest.raises(RuntimeError, match="agent crashed"):
        replay.run(get_feed_item("x-attack-direct"))
    assert world.calls["chain"] == ["evm_snapshot", "evm_revert"]


def test_the_revert_runs_when_the_drainer_raises(world, monkeypatch):
    def boom():
        raise RuntimeError("drain crashed")
    monkeypatch.setattr(replay.drainer, "drain", boom)
    with pytest.raises(RuntimeError):
        replay.run(get_feed_item("x-attack-direct"))
    assert world.calls["chain"] == ["evm_snapshot", "evm_revert"]


def test_a_failed_revert_is_reported_not_hidden(world, monkeypatch):
    original = replay.chain.get_web3()

    def failing(method, params):
        world.calls["chain"].append(method)
        return {"result": "0x1"} if method == "evm_snapshot" else {"result": False}
    monkeypatch.setattr(replay.chain, "get_web3", lambda: SimpleNamespace(
        is_connected=lambda: True, eth=SimpleNamespace(chain_id=31337), provider=SimpleNamespace(make_request=failing)))
    assert replay.run(get_feed_item("x-attack-direct"))["chain_reset"] is False


def test_nothing_is_snapshotted_or_reverted_on_a_refused_replay(world, monkeypatch):
    monkeypatch.setattr(replay.chain, "network", lambda: "sepolia")
    assert client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).status_code == 403
    monkeypatch.setattr(replay.chain, "network", lambda: "local")
    assert client.post("/api/attack-replay", json={"attack_id": "x-benign-1"}).status_code == 400            # not an attack
    monkeypatch.setattr(replay.chain, "get_web3", lambda: SimpleNamespace(
        is_connected=lambda: True, eth=SimpleNamespace(chain_id=11155111),
        provider=SimpleNamespace(make_request=lambda m, p: world.calls["chain"].append(m))))
    assert client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).status_code == 403
    assert world.calls["chain"] == []


# ------------------------------------------------------------------ the feed endpoint

def test_feed_endpoint_returns_synthetic_items():
    items = client.get("/api/feed").json()["items"]
    assert len(items) == 9 and sum(item["attack"] for item in items) == 6
    assert all(item["origin"] in {"public_feed", "nft_metadata"} for item in items)


# ------------------------------------------------------------------ one extracted action, two agents

def test_both_agents_get_the_same_action_and_the_code_assigned_origin(world):
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    (p_intent, p_origin), (n_intent, n_origin) = world.calls["protected"][0], world.calls["naive"][0]
    assert p_intent == n_intent == approve_intent()
    assert p_origin == n_origin == "public_feed"
    assert body["intent"]["source"] == "llm" and body["intent"]["action"] == "approve"


def test_the_naive_agent_loses_everything_and_the_protected_agent_shows_the_rules(world):
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    assert body["naive"] == {"status": "drained", "tx_hash": "0xnaive", "drain_tx_hash": "0xdrain",
                             "balance_before": "1000", "balance_after": "0", "balance_drop": "1000",
                             "reason": "Naive agent executed the LLM-extracted request."}
    assert body["protected"]["status"] == "blocked"
    assert body["protected"]["decision"]["rule_ids"] == ["PRV-01", "APR-01"]
    assert world.calls["drain"] == 1


def test_the_protected_agent_runs_before_the_naive_one_changes_the_chain(world, monkeypatch):
    order = []
    original = replay.protected.handle_intent
    monkeypatch.setattr(replay.protected, "handle_intent", lambda intent, origin: order.append("protected") or original(intent, origin))
    original_naive = replay.naive_agent.handle_intent
    monkeypatch.setattr(replay.naive_agent, "handle_intent", lambda intent, origin: order.append("naive") or original_naive(intent, origin))
    client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"})
    assert order == ["protected", "naive"]


def test_a_direct_transfer_attack_is_measured_by_the_balance_without_a_drain(world, monkeypatch):
    monkeypatch.setattr(replay, "parse_intent", fooled_model(transfer_intent()))
    body = client.post("/api/attack-replay", json={"attack_id": "nft-attack-admin"}).json()
    assert body["naive"]["status"] == "stolen"
    assert (body["naive"]["balance_before"], body["naive"]["balance_after"], body["naive"]["balance_drop"]) == ("1000", "990", "10")
    assert world.calls["drain"] == 0 and body["naive"]["drain_tx_hash"] is None


def test_an_approval_that_cannot_be_drained_is_reported_not_hidden(world, monkeypatch):
    def refused():
        raise replay.drainer.DrainRefused("The victim holds no tokens")
    monkeypatch.setattr(replay.drainer, "drain", refused)
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    assert body["naive"]["status"] == "approved" and "The victim holds no tokens" in body["naive"]["reason"]


def test_when_the_naive_agent_fails_the_page_says_so(world, monkeypatch):
    monkeypatch.setattr(replay.naive_agent, "handle_intent",
                        lambda intent, origin: AgentReply(text="The naive demo agent could not complete the request.", blocked=True))
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    assert body["naive"]["status"] == "failed" and body["naive"]["balance_drop"] is None
    assert body["protected"]["status"] == "blocked"


# ------------------------------------------------------------------ real model or script

@pytest.mark.parametrize("attack_id", ATTACKS)
def test_every_attack_has_a_scripted_fooled_intent_when_the_model_gives_nothing(world, monkeypatch, attack_id):
    def refuses(text, **kwargs):
        raise IntentParseError()
    monkeypatch.setattr(replay, "parse_intent", refuses)
    body = client.post("/api/attack-replay", json={"attack_id": attack_id}).json()
    assert body["intent"]["source"] == "scripted" and "no usable action" in body["intent"]["note"]
    assert body["intent"]["to"] == ATTACKER and body["intent"]["action"] in ("approve", "transfer")
    assert world.calls["protected"][0][0] == world.calls["naive"][0][0]


def test_a_model_action_that_does_not_pay_the_attacker_is_replaced_by_the_script(world, monkeypatch):
    monkeypatch.setattr(replay, "parse_intent", fooled_model(transfer_intent(to="0x" + "cd" * 20)))
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    assert body["intent"]["source"] == "scripted" and body["intent"]["to"] == ATTACKER
    assert "did not target the attacker" in body["intent"]["note"]


def test_a_missing_model_does_not_stop_the_replay(world, monkeypatch):
    def no_key(text, **kwargs):
        raise RuntimeError("Missing in .env: LLM_API_KEY")
    monkeypatch.setattr(replay, "parse_intent", no_key)
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-base64"}).json()
    assert body["intent"]["source"] == "scripted" and body["layer1"]["status"] == "unreachable"      # not 'refused'
    assert "could not be reached" in body["intent"]["note"] and "RuntimeError" in body["layer1"]["detail"]


def test_layer_one_reports_whether_the_wrapper_stopped_the_model(world, monkeypatch):
    def wrapped_refuses_plain_obeys(text, untrusted=False, **kwargs):
        if untrusted:
            raise IntentParseError()
        return approve_intent()
    monkeypatch.setattr(replay, "parse_intent", wrapped_refuses_plain_obeys)
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    assert body["layer1"]["status"] == "refused" and body["intent"]["source"] == "llm"

    monkeypatch.setattr(replay, "parse_intent", fooled_model(approve_intent()))
    assert client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()["layer1"]["status"] == "fooled"


def test_the_payload_is_the_feed_text_with_only_the_addresses_pointed_at_the_attacker(world):
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    item = get_feed_item("x-attack-direct")
    assert body["attack"]["text"] == item.text
    assert body["attack"]["payload"] == item.text.replace("0x0000000000000000000000000000000000000BAD", ATTACKER)
    assert "for this local security replay" not in body["attack"]["payload"].lower()      # nothing is added to the attack


# ------------------------------------------------------------------ refusals

def test_attack_replay_rejects_benign_item(world):
    reply = client.post("/api/attack-replay", json={"attack_id": "x-benign-1"})
    assert reply.status_code == 400 and "attack item" in reply.json()["detail"]
    assert world.calls["protected"] == [] and world.calls["naive"] == []


def test_attack_replay_rejects_unknown_item(world):
    assert client.post("/api/attack-replay", json={"attack_id": "not-real"}).status_code == 404


def test_attack_replay_refuses_non_local_network_before_anything_runs(monkeypatch, world):
    monkeypatch.setattr(replay.chain, "network", lambda: "sepolia")
    assert client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).status_code == 403
    assert world.calls["protected"] == [] and world.calls["naive"] == [] and world.calls["drain"] == 0


def test_attack_replay_refuses_a_node_that_is_not_chain_31337(monkeypatch, world):
    monkeypatch.setattr(replay.chain, "get_web3", lambda: SimpleNamespace(
        is_connected=lambda: True, eth=SimpleNamespace(chain_id=11155111)))
    assert client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).status_code == 403
    assert world.calls["naive"] == []


def test_an_unexpected_error_does_not_leak_details(world, monkeypatch):
    def boom(intent, origin):
        raise RuntimeError("https://eth-sepolia.g.alchemy.com/v2/SECRETKEY123456")
    monkeypatch.setattr(replay.protected, "handle_intent", boom)
    reply = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"})
    assert reply.status_code == 503 and "SECRETKEY" not in reply.text and "alchemy" not in reply.text


# ------------------------------------------------------------------ live: the real agents on a real local chain

def test_live_two_replays_in_a_row_are_identical_and_leave_the_chain_untouched(monkeypatch):
    from wallet_engine import chain
    import wallet_engine
    try:
        info = chain.status()
    except Exception:
        pytest.skip("chain not configured")
    if not (info.get("connected") and info.get("chain_id") == 31337 and info.get("token_deployed") and chain.network() == "local"):
        pytest.skip("local anvil with deployed TestUSD not available")
    if not os.getenv("ATTACKER_PRIVATE_KEY"):
        pytest.skip("ATTACKER_PRIVATE_KEY not set")

    def no_model(text, **kwargs):
        raise IntentParseError()
    monkeypatch.setattr(replay, "parse_intent", no_model)
    w3 = chain.get_web3()
    outer = w3.provider.make_request("evm_snapshot", [])["result"]       # safety net for the test only
    try:
        start = Decimal(wallet_engine.balances()["TUSD"])
        first = replay.run(get_feed_item("x-attack-direct"))
        middle = Decimal(wallet_engine.balances()["TUSD"])
        second = replay.run(get_feed_item("x-attack-direct"))
        end = Decimal(wallet_engine.balances()["TUSD"])
    finally:
        w3.provider.make_request("evm_revert", [outer])
    assert first["naive"]["status"] == second["naive"]["status"] == "drained"
    assert Decimal(first["naive"]["balance_before"]) == Decimal(second["naive"]["balance_before"]) == start
    assert first["naive"]["balance_drop"] == second["naive"]["balance_drop"]
    assert middle == start == end and first["chain_reset"] is second["chain_reset"] is True
    assert first["protected"]["decision"]["rule_ids"] == second["protected"]["decision"]["rule_ids"]

def test_live_replay_on_anvil_the_naive_agent_is_drained_and_the_firewall_names_its_rules(monkeypatch):
    from wallet_engine import chain
    try:
        info = chain.status()
    except Exception:
        pytest.skip("chain not configured")
    if not (info.get("connected") and info.get("chain_id") == 31337 and info.get("token_deployed") and chain.network() == "local"):
        pytest.skip("local anvil with deployed TestUSD not available")
    if not os.getenv("ATTACKER_PRIVATE_KEY"):
        pytest.skip("ATTACKER_PRIVATE_KEY not set")

    def no_model(text, **kwargs):
        raise IntentParseError()
    monkeypatch.setattr(replay, "parse_intent", no_model)           # no LLM, no network: the scripted fooled intent
    w3 = chain.get_web3()
    snapshot = w3.provider.make_request("evm_snapshot", [])["result"]
    try:
        import wallet_engine
        before = Decimal(wallet_engine.balances()["TUSD"])
        body = replay.run(get_feed_item("x-attack-direct"))
        after = Decimal(wallet_engine.balances()["TUSD"])
    finally:
        w3.provider.make_request("evm_revert", [snapshot])
    assert body["intent"]["source"] == "scripted"
    assert body["naive"]["status"] == "drained" and Decimal(body["naive"]["balance_drop"]) == before
    assert Decimal(body["naive"]["balance_after"]) == 0           # the result shows the loss ...
    assert after == before and body["chain_reset"] is True        # ... and the chain was rolled back afterwards
    assert body["protected"]["status"] == "blocked"
    rules = body["protected"]["decision"]["rule_ids"]
    assert "PRV-01" in rules and "APR-01" in rules               # the firewall, not the model, stopped it
    assert body["protected"]["tx_hash"] is None


# ------------------------------------------------------------------ an outage is not a refusal

def _parse_error(cause):
    error = IntentParseError()
    error.__cause__ = cause          # what parse_intent does: `raise IntentParseError() from last_error`
    return error


@pytest.mark.parametrize("cause", [ConnectionError("provider unreachable"), TimeoutError("read timed out"),
                                   RuntimeError("Missing in .env: LLM_API_KEY")])
def test_an_outage_behind_intent_parse_error_is_reported_as_unreachable(world, monkeypatch, cause):
    def down(text, **kwargs):
        raise _parse_error(cause)
    monkeypatch.setattr(replay, "parse_intent", down)
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    assert body["layer1"]["status"] == "unreachable" and type(cause).__name__ in body["layer1"]["detail"]
    assert "refused" not in body["layer1"]["detail"] and "could not be reached" in body["intent"]["note"]
    assert body["intent"]["source"] == "scripted"


@pytest.mark.parametrize("cause", [ValueError("response was not valid JSON"), ValueError("unsupported action"), None])
def test_a_real_refusal_or_bad_reply_is_still_reported_as_refused(world, monkeypatch, cause):
    def no_action(text, **kwargs):
        raise _parse_error(cause)
    monkeypatch.setattr(replay, "parse_intent", no_action)
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    assert body["layer1"]["status"] == "refused" and "no usable action" in body["intent"]["note"]


def test_the_real_parse_intent_keeps_the_cause_so_an_outage_is_not_a_refusal(world, monkeypatch):
    """End to end through the real parse_intent (only the HTTP call is replaced)."""
    import agent.intents as intents
    from agent.intents import parse_intent as real_parse

    def down(messages):
        raise ConnectionError("provider unreachable")
    monkeypatch.setattr(intents, "_llm_call", down)
    monkeypatch.setattr(replay, "parse_intent", real_parse)
    body = client.post("/api/attack-replay", json={"attack_id": "x-attack-direct"}).json()
    assert body["layer1"]["status"] == "unreachable" and "ConnectionError" in body["layer1"]["detail"]
