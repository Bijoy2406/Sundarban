"""API smoke tests (Person 3). Uses FastAPI's TestClient, no server needed."""
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_health_always_answers():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["backend"] == "ok"
    assert {"network", "connected"} <= set(body["chain"])
    assert {"base_url", "model", "api_key_set"} == set(body["llm"])


def test_llm_status_never_returns_the_key():
    r = client.get("/api/llm/status")
    assert r.status_code == 200
    assert "api_key" not in r.json()          # only api_key_set (true/false)


def test_plan_rejects_unknown_action():
    r = client.post("/api/plan", json={"action": "steal", "to": "0x0", "amount": "1"})
    assert r.status_code == 422
