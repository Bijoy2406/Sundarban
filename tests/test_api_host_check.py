"""DNS rebinding: a web page can make its own hostname resolve to 127.0.0.1 and then call this API as the owner
(chat -> read the request id -> /api/confirm). The API therefore accepts only local Host names."""
import pytest
from fastapi.testclient import TestClient

import api.main as api
from firewall import state


@pytest.mark.parametrize("host", ["localhost", "localhost:8000", "127.0.0.1", "127.0.0.1:8000", "testserver"])
def test_local_host_names_are_served(host):
    assert TestClient(api.app).get("/api/security", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "localhost.evil.example", "127.0.0.1.evil.example",
                                  "0.0.0.0", "192.168.1.20:8000", ""])
def test_any_other_host_name_is_refused(host):
    reply = TestClient(api.app).get("/api/security", headers={"Host": host})
    assert reply.status_code == 400


def test_a_rebound_page_cannot_switch_the_kill_switch_off_or_confirm():
    client = TestClient(api.app)
    state.set_kill_switch(True)
    evil = {"Host": "evil.example:8000", "Origin": "http://evil.example:8000"}
    assert client.post("/api/kill-switch", json={"enabled": False}, headers=evil).status_code == 400
    assert client.post("/api/confirm", json={"request_id": "anything"}, headers=evil).status_code == 400
    assert client.post("/api/chat", json={"message": "send 1 TUSD"}, headers=evil).status_code == 400
    assert state.kill_switch_on() is True
