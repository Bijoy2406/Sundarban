"""One shared helper for tests that call the two operator-protected endpoints (POST /api/confirm and POST
/api/kill-switch with enabled=false). conftest.py sets OPERATOR_TOKEN to this value for every test."""
OPERATOR_TOKEN = "test-operator-key-0123456789abcdef"


def operator_headers(token: str = OPERATOR_TOKEN) -> dict:
    return {"X-Operator-Token": token}
