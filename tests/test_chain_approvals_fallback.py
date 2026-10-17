"""approvals() on a public network whose RPC refuses wide log searches (Alchemy free tier allows 10 blocks)."""
from types import SimpleNamespace

import pytest
from web3 import Web3

from wallet_engine import chain

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BOB = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
OWNER = "0x" + "11" * 20
TOKEN = Web3.to_checksum_address("0x" + "22" * 20)


class FakeToken:
    address = TOKEN

    def __init__(self, allowances, scan_error=None, logged=()):
        self._allowances, self._scan_error, self._logged = allowances, scan_error, logged
        self.functions = SimpleNamespace(
            decimals=lambda: SimpleNamespace(call=lambda: 18),
            allowance=lambda owner, spender: SimpleNamespace(call=lambda: self._allowances.get(spender, 0)))
        self.events = SimpleNamespace(Approval=lambda: SimpleNamespace(get_logs=self._get_logs))

    def _get_logs(self, **kwargs):
        if self._scan_error:
            raise self._scan_error
        return [{"args": {"spender": s}} for s in self._logged]


@pytest.fixture
def setup(monkeypatch, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(f'allowlist:\n  - "{ALICE}"\n  - "{BOB}"\n', encoding="utf-8")
    monkeypatch.setenv("RULES_PATH", str(rules))
    monkeypatch.delenv("ATTACKER_PRIVATE_KEY", raising=False)
    monkeypatch.setattr(chain, "get_web3", lambda: object())
    monkeypatch.setattr(chain, "wallet_address", lambda: OWNER)
    monkeypatch.setattr(chain, "token_address", lambda: TOKEN)
    monkeypatch.setattr(chain, "_deploy_block", lambda: 0)

    def use(token, net):
        monkeypatch.setattr(chain, "token_contract", lambda w3, address: token)
        monkeypatch.setenv("ACTIVE_NETWORK", net)
    return use


def test_normal_scan_is_used_when_it_works(setup):
    setup(FakeToken({ALICE: 5 * 10**18}, logged=[ALICE, ALICE]), "sepolia")
    assert chain.approvals() == [{"token": TOKEN, "spender": ALICE, "allowance": "5"}]


def test_public_network_falls_back_to_the_known_spenders(setup):
    refused = RuntimeError("Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range")
    setup(FakeToken({BOB: 10**18}, scan_error=refused), "sepolia")
    assert chain.approvals() == [{"token": TOKEN, "spender": BOB, "allowance": "1"}]


def test_fallback_with_no_active_approval_is_an_empty_list(setup):
    setup(FakeToken({}, scan_error=RuntimeError("range")), "sepolia")
    assert chain.approvals() == []


def test_the_local_chain_never_hides_a_scan_error(setup):
    setup(FakeToken({BOB: 10**18}, scan_error=RuntimeError("boom")), "local")
    with pytest.raises(RuntimeError, match="boom"):
        chain.approvals()


def test_candidates_include_the_attacker_and_ignore_junk(monkeypatch, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(f'allowlist:\n  - "{ALICE.lower()}"\n  - "not-an-address"\n', encoding="utf-8")
    monkeypatch.setenv("RULES_PATH", str(rules))
    monkeypatch.setenv("ATTACKER_PRIVATE_KEY", "0x" + "ab" * 32)
    attacker = Web3().eth.account.from_key("0x" + "ab" * 32).address
    assert chain._candidate_spenders() == sorted([ALICE, attacker])


def test_candidates_survive_a_missing_rules_file(monkeypatch, tmp_path):
    monkeypatch.setenv("RULES_PATH", str(tmp_path / "nope.yaml"))
    monkeypatch.delenv("ATTACKER_PRIVATE_KEY", raising=False)
    assert chain._candidate_spenders() == []
