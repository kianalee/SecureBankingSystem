from fastapi.testclient import TestClient

import secure_banking.gateway as gateway
from secure_banking.session_store import SessionStore


class FakeATMProtocolClient:
    def __init__(self):
        self.client_id = None
        self.connected = False
        self.authenticated = False
        self.authenticated_email = None
        self.balance_value = 880.0
        self.phase = "disconnected"
        self.protocol_events = []
        self.last_action = None

    def connect(self, client_id: str):
        self.client_id = client_id
        self.connected = True
        self.phase = "phase2"
        self.protocol_events = [
            {
                "timestamp": "2026-03-25T12:00:00+00:00",
                "phase": "phase1",
                "title": "Connecting",
                "detail": "Opening secure channel.",
            }
        ]
        return self.status_payload()

    def register(self, username: str, email: str, password: str):
        self.last_action = "REGISTER"
        return {"status": "ok", "msg": "Registration successful", "username": username, "email": email}

    def login(self, email: str, password: str):
        self.authenticated = True
        self.authenticated_email = email
        self.last_action = "LOGIN"
        return {"status": "ok", "msg": "Login successful", "uid": "uid-1"}

    def logout(self):
        self.authenticated = False
        self.authenticated_email = None
        self.last_action = "LOGOUT"
        return {"status": "ok", "msg": "Logged out successfully"}

    def balance(self):
        self.last_action = "BALANCE"
        return {"status": "ok", "balance": self.balance_value}

    def deposit(self, amount: float):
        self.last_action = "DEPOSIT"
        self.balance_value += amount
        return {"status": "ok", "balance": self.balance_value}

    def withdraw(self, amount: float):
        self.last_action = "WITHDRAW"
        self.balance_value -= amount
        return {"status": "ok", "balance": self.balance_value}

    def close(self, send_exit: bool = True):
        self.connected = False
        self.last_action = "EXIT" if send_exit else self.last_action

    def status_payload(self):
        return {
            "clientId": self.client_id,
            "connected": self.connected,
            "authenticated": self.authenticated,
            "authenticatedEmail": self.authenticated_email,
            "phase": self.phase,
            "lastAction": self.last_action,
            "connectedAt": "2026-03-25T12:00:00+00:00",
            "lastActivityAt": "2026-03-25T12:00:00+00:00",
            "protocolEvents": self.protocol_events,
            "protocolSummary": {
                "secureChannel": self.connected,
                "phase1Complete": self.connected,
                "phase2Complete": self.connected,
            },
        }


def create_client(monkeypatch):
    monkeypatch.setattr(gateway, "ATMProtocolClient", FakeATMProtocolClient)
    monkeypatch.setattr(gateway, "store", SessionStore())
    monkeypatch.setattr(gateway, "get_admin_panel_password", lambda: "secret123")
    monkeypatch.setattr(
        gateway,
        "fetch_audit_logs",
        lambda limit=20: {
            "available": True,
            "message": "ok",
            "logs": [{"id": "1", "email": "person@example.com", "action": "BALANCE INQUIRY", "time": "2026-03-25T12:00:00+00:00"}],
        },
    )
    monkeypatch.setattr(
        gateway,
        "check_bank_server_health",
        lambda: {"reachable": True, "host": "localhost", "port": 1234, "message": "reachable"},
    )
    return TestClient(gateway.app)


def test_connect_then_query_balance(monkeypatch):
    client = create_client(monkeypatch)

    connect_response = client.post("/api/session/connect", json={"clientId": "ATM Aurora"})
    assert connect_response.status_code == 200
    assert connect_response.json()["status"] == "ok"

    login_response = client.post("/api/auth/login", json={"email": "person@example.com", "password": "password123"})
    assert login_response.status_code == 200
    assert login_response.json()["data"]["uid"] == "uid-1"

    balance_response = client.get("/api/account/balance")
    assert balance_response.status_code == 200
    assert balance_response.json()["data"]["balance"] == 880.0


def test_invalid_amount_rejected(monkeypatch):
    client = create_client(monkeypatch)
    client.post("/api/session/connect", json={"clientId": "ATM Aurora"})

    response = client.post("/api/account/deposit", json={"amount": 0})
    assert response.status_code == 400
    assert response.json()["message"] == "Amount must be greater than 0."


def test_admin_overview_includes_sessions_and_logs(monkeypatch):
    client = create_client(monkeypatch)
    admin_login = client.post("/api/admin/auth/login", json={"password": "secret123"})
    assert admin_login.status_code == 200

    client.post("/api/session/connect", json={"clientId": "ATM Aurora"})

    overview = client.get("/api/admin/overview")
    payload = overview.json()["data"]

    assert overview.status_code == 200
    assert payload["server"]["reachable"] is True
    assert payload["sessions"]["count"] == 1
    assert payload["audit"]["items"][0]["action"] == "BALANCE INQUIRY"


def test_admin_endpoints_require_login(monkeypatch):
    client = create_client(monkeypatch)
    response = client.get("/api/admin/overview")
    assert response.status_code == 401
    assert response.json()["message"] == "Admin login required."


def test_session_peek_returns_guest_without_cookie(monkeypatch):
    client = create_client(monkeypatch)
    response = client.get("/api/session/peek")
    assert response.status_code == 200
    assert response.json()["data"]["connected"] is False
