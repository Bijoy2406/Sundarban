"""execute(): a broadcast transaction without a receipt is 'pending', not 'failed'; sends never share a nonce.

Offline: a fake node stands in for the chain, so these run without Anvil.
"""
import importlib
import threading
import time
import uuid

import pytest
from eth_account.typed_transactions import TypedTransaction
from fastapi.testclient import TestClient
from hexbytes import HexBytes
from web3 import Web3

import agent.agent as protected
import api.main as api
import wallet_engine
from firewall import audit, tokens
from shared.types import ActionRequest, AgentReply, Decision, TxPlan
from wallet_engine import chain, erc20

execute = importlib.import_module("wallet_engine.execute")     # the package also exports a function named execute

KEY = "0x" + "01" * 31 + "02"
ACCOUNT = Web3().eth.account.from_key(KEY)
TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


class FakeEth:
    account = Web3().eth.account
    chain_id = 31337

    def __init__(self, wait=None, send_delay=0.0, send_error=None):
        self.wait, self.send_delay, self.send_error = wait, send_delay, send_error
        self.next_nonce, self.nonces_used, self.sent = 0, [], []
        self._lock = threading.Lock()
        self.gas_price, self.max_priority_fee = 10**9, 10**9

    def get_block(self, name):
        return {"baseFeePerGas": 10**9}

    def get_transaction_count(self, address, state):
        with self._lock:
            return self.next_nonce

    def send_raw_transaction(self, raw):
        if self.send_error:
            raise self.send_error
        decoded = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()      # the nonce that was really signed
        time.sleep(self.send_delay)                      # a window in which a second sender could read the same nonce
        with self._lock:
            self.nonces_used.append(self.next_nonce)
            self.next_nonce += 1
            self.sent.append(decoded)
        return bytes.fromhex("ab" * 32)

    def wait_for_transaction_receipt(self, tx_hash, timeout):
        if self.wait:
            return self.wait()
        return type("Receipt", (), {"status": 1})()


class FakeWeb3:
    def __init__(self, eth):
        self.eth = eth

    def is_connected(self):
        return True


def make_plan(amount="5"):
    req = ActionRequest(request_id=str(uuid.uuid4()), action="transfer", token=TOKEN, to=ALICE, amount=amount,
                        unlimited=False, origin="user_chat")
    data = Web3().eth.contract(abi=erc20.ERC20_ABI).encode_abi("transfer", args=[ALICE, erc20.to_base_units(amount)])
    plan = TxPlan(chain_id=31337, from_addr=ACCOUNT.address, to=TOKEN, value=0, data=data, gas=60_000,
                  function="transfer(address,uint256)", args={}, summary=f"Send {amount} TUSD")
    return req, plan


def allow(req, plan):
    from wallet_engine.binding import token_binding
    b = token_binding(plan)
    token = tokens.issue_token(req.request_id, b["action"], b["token"], b["to"], b["amount"])
    return Decision(req.request_id, "allow", ["ALLOW"], ["ok"], token)


@pytest.fixture
def node(monkeypatch):
    monkeypatch.setenv("ACTIVE_NETWORK", "local")
    monkeypatch.setenv("WALLET_PRIVATE_KEY", KEY)
    holder = {}

    def install(eth):
        holder["eth"] = eth
        monkeypatch.setattr(chain, "get_web3", lambda: FakeWeb3(eth))
        monkeypatch.setattr(execute, "simulate_run", lambda plan: type("S", (), {"ok": True, "revert_reason": None})())
        return eth
    return install


# ------------------------------------------------------------------ pending vs failed

def test_no_receipt_in_time_is_pending_with_the_hash_and_never_failed(node):
    def slow():
        raise TimeoutError("not mined within 120 seconds")
    node(FakeEth(wait=slow))
    req, plan = make_plan()
    with pytest.raises(execute.ExecutionPending) as caught:
        wallet_engine.execute(plan, allow(req, plan))
    assert caught.value.tx_hash == "0x" + "ab" * 32
    assert "do not send it twice" in str(caught.value) and "failed" not in str(caught.value).lower()
    events = [e["event"].get("event") for e in audit.tail(10)]
    assert events == ["TX_SENT", "TX_PENDING"]


def test_a_mined_but_reverted_transaction_is_still_a_failure(node):
    node(FakeEth(wait=lambda: type("Receipt", (), {"status": 0})()))
    req, plan = make_plan()
    with pytest.raises(execute.ExecutionFailed):
        wallet_engine.execute(plan, allow(req, plan))


def test_a_confirmed_transaction_returns_its_hash(node):
    node(FakeEth())
    req, plan = make_plan()
    assert wallet_engine.execute(plan, allow(req, plan)) == "0x" + "ab" * 32


# ------------------------------------------------------------------ nonce

def test_two_simultaneous_sends_never_share_a_nonce(node):
    eth = node(FakeEth(send_delay=0.05))
    jobs = [make_plan(str(n)) for n in range(1, 7)]
    decisions = [allow(r, p) for r, p in jobs]
    errors = []

    def send(job, decision):
        try:
            wallet_engine.execute(job[1], decision)
        except Exception as exc:                          # pragma: no cover - reported by the assertion below
            errors.append(exc)
    threads = [threading.Thread(target=send, args=(j, d)) for j, d in zip(jobs, decisions)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    assert sorted(t["nonce"] for t in eth.sent) == [0, 1, 2, 3, 4, 5]


# ------------------------------------------------------------------ what the agent and the API say

def test_the_agent_reports_a_pending_transaction_with_its_hash():
    exc = execute.ExecutionPending("0x" + "cd" * 32)
    reply = protected._pending_reply(exc, Decision("r", "allow", ["ALLOW"], [], "t"))
    assert reply.tx_hash == "0x" + "cd" * 32 and reply.blocked is False
    assert protected.is_pending(reply) is True
    assert protected.is_pending(AgentReply(text="Done. Transaction: 0x1", tx_hash="0x1")) is False
    assert protected.is_pending(AgentReply(text="Nothing was sent.", blocked=True)) is False


def test_chat_and_execute_endpoints_say_pending(monkeypatch):
    client = TestClient(api.app)
    pending = execute.ExecutionPending("0x" + "ef" * 32)
    monkeypatch.setattr(api, "handle_agent_message", lambda text, origin: protected._pending_reply(
        pending, Decision("r", "allow", ["ALLOW"], [], "t")))
    chat = client.post("/api/chat", json={"message": "send 5 TUSD to someone"}).json()
    assert chat["status"] == "pending" and chat["tx_hash"] == "0x" + "ef" * 32

    req, plan = make_plan()
    monkeypatch.setattr(api, "_plan_simulate_evaluate", lambda r: (plan, None, allow(req, plan)))
    monkeypatch.setattr(api.wallet_engine, "execute", lambda p, d: (_ for _ in ()).throw(pending))
    body = client.post("/api/execute", json={"action": "transfer", "to": ALICE, "amount": "5"}).json()
    assert body["status"] == "pending" and body["tx_hash"] == "0x" + "ef" * 32 and body["executed"] is False
    assert "do not send it twice" in body["message"]


# ------------------------------------------------------------------ the broadcast itself fails or times out

class SendFails(FakeEth):
    """The node may have accepted the transaction, but the answer never came back."""

    def __init__(self, error):
        super().__init__()
        self.error, self.raw_seen = error, []

    def send_raw_transaction(self, raw):
        self.raw_seen.append(bytes(raw))
        raise self.error


@pytest.mark.parametrize("error", [TimeoutError("read timed out"), ConnectionError("connection reset by peer")])
def test_a_send_that_raises_after_signing_is_pending_with_the_signed_hash(node, error):
    """Neither 'failed' nor 'sent': the transaction may still be mined. The hash is computed from the signed bytes,
    so the person can look it up and a retry does not pay twice."""
    eth = node(SendFails(error))
    req, plan = make_plan()
    with pytest.raises(execute.ExecutionPending) as caught:
        wallet_engine.execute(plan, allow(req, plan))
    expected = "0x" + Web3.keccak(eth.raw_seen[0]).hex().removeprefix("0x")
    assert caught.value.tx_hash == expected
    assert "do not send it twice" in str(caught.value)
    assert [e["event"].get("event") for e in audit.tail(10)] == ["TX_PENDING"]
    assert audit.tail(10)[0]["event"]["tx_hash"] == expected


def test_the_agent_and_the_api_report_a_failed_send_as_pending_not_failed(node, monkeypatch):
    node(SendFails(TimeoutError("read timed out")))
    req, plan = make_plan()
    decision = allow(req, plan)
    monkeypatch.setattr(api, "_plan_simulate_evaluate", lambda r: (plan, None, decision))
    response = TestClient(api.app).post("/api/execute", json={"action": "transfer", "to": ALICE, "amount": "5"})
    assert response.status_code == 200
    assert response.json()["status"] == "pending" and response.json()["tx_hash"].startswith("0x")


# ------------------------------------------------------------------ a node's "no" is a refusal; a silence is pending

@pytest.mark.parametrize("message", ["nonce too low: next nonce 7, tx nonce 3", "replacement transaction underpriced",
                                     "insufficient funds for gas * price + value"])
def test_a_json_rpc_rejection_is_a_refusal_not_pending(node, message):
    from web3.exceptions import Web3RPCError
    node(FakeEth(send_error=Web3RPCError(message)))
    req, plan = make_plan()
    with pytest.raises(execute.ExecutionRefused, match="rejected the transaction"):
        wallet_engine.execute(plan, allow(req, plan))
    assert [e["event"].get("event") for e in audit.tail(10)] == ["EXECUTE_REFUSED"]       # no TX_PENDING for a tx that never existed


def test_the_old_style_value_error_rpc_answer_is_also_a_refusal(node):
    node(FakeEth(send_error=ValueError({"code": -32000, "message": "nonce too low"})))
    req, plan = make_plan()
    with pytest.raises(execute.ExecutionRefused):
        wallet_engine.execute(plan, allow(req, plan))


def test_a_rejection_message_does_not_leak_the_rpc_url(node):
    from web3.exceptions import Web3RPCError
    node(FakeEth(send_error=Web3RPCError("nonce too low for https://eth-sepolia.g.alchemy.com/v2/SECRETKEY0123456789")))
    req, plan = make_plan()
    with pytest.raises(execute.ExecutionRefused) as caught:
        wallet_engine.execute(plan, allow(req, plan))
    assert "SECRETKEY" not in str(caught.value) and "alchemy" not in str(caught.value)


def test_already_known_means_it_is_in_the_mempool_so_it_stays_pending(node):
    from web3.exceptions import Web3RPCError
    node(FakeEth(send_error=Web3RPCError("already known")))
    req, plan = make_plan()
    with pytest.raises(execute.ExecutionPending):
        wallet_engine.execute(plan, allow(req, plan))


@pytest.mark.parametrize("error", [ConnectionError("connection reset"), TimeoutError("read timed out")])
def test_a_timeout_or_dropped_connection_stays_pending(node, error):
    node(FakeEth(send_error=error))
    req, plan = make_plan()
    with pytest.raises(execute.ExecutionPending) as caught:
        wallet_engine.execute(plan, allow(req, plan))
    assert caught.value.tx_hash.startswith("0x") and len(caught.value.tx_hash) == 66
