"""API authentication.

Every route that can approve containment, wipe the database, or inject events must
reject unauthenticated callers. The backend runs with sudo, so an open endpoint here is
equivalent to handing out root.

The FastAPI lifespan is deliberately not run — these tests exercise routing and auth,
not watchers or packet capture.
"""

import pytest
from fastapi.testclient import TestClient

from backend.config import API_TOKEN
from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


AUTH = {"Authorization": f"Bearer {API_TOKEN}"}

# (method, path) for every route that must be protected.
PROTECTED_ROUTES = [
    ("get", "/api/telemetry"),
    ("get", "/api/threats"),
    ("get", "/api/logs"),
    ("get", "/api/logs/all"),
    ("delete", "/api/logs/all"),
    ("get", "/api/connections"),
    ("get", "/api/blocks"),
    ("post", "/api/blocks/1.2.3.4/release"),
    ("post", "/api/threats/approve-all"),
    ("post", "/api/threats/ABC123/approve"),
    ("post", "/api/threats/ABC123/dismiss"),
    ("post", "/api/test/inject"),
    ("post", "/api/test/inject-auto"),
    ("post", "/api/test/inject-lateral"),
    ("post", "/api/test/inject-ransomware"),
]


@pytest.mark.parametrize("method,path", PROTECTED_ROUTES)
def test_route_rejects_unauthenticated_request(client, method, path):
    response = getattr(client, method)(path)
    assert response.status_code == 401, f"{method.upper()} {path} is unauthenticated!"


@pytest.mark.parametrize("method,path", PROTECTED_ROUTES)
def test_route_rejects_wrong_token(client, method, path):
    response = getattr(client, method)(path, headers={"Authorization": "Bearer wrong-token"})
    assert response.status_code == 401


def test_valid_token_is_accepted(client):
    assert client.get("/api/telemetry", headers=AUTH).status_code == 200


def test_token_query_parameter_also_works(client):
    assert client.get(f"/api/telemetry?token={API_TOKEN}").status_code == 200


def test_malformed_authorization_header_rejected(client):
    for header in ["", "Bearer", "Basic abc", f"Token {API_TOKEN}", API_TOKEN]:
        r = client.get("/api/telemetry", headers={"Authorization": header})
        assert r.status_code == 401, header


# ===== Login =====

def test_login_is_public_and_returns_the_token(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "phantom"})
    assert r.status_code == 200
    assert r.json()["token"] == API_TOKEN


@pytest.mark.parametrize("body", [
    {"username": "admin", "password": "wrong"},
    {"username": "root", "password": "phantom"},
    {"username": "", "password": ""},
])
def test_login_rejects_bad_credentials(client, body):
    r = client.post("/api/auth/login", json=body)
    assert r.status_code == 401
    assert "token" not in r.json()


def test_login_error_does_not_disclose_which_field_was_wrong(client):
    bad_user = client.post("/api/auth/login", json={"username": "nope", "password": "phantom"})
    bad_pass = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert bad_user.json() == bad_pass.json()


# ===== WebSocket =====

def test_websocket_rejects_missing_token(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws"):
            pass


def test_websocket_rejects_bad_token(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws?token=wrong"):
            pass
