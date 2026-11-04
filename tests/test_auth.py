"""User accounts, stateless JWT bearer tokens, roles and login throttling."""

import time

import jwt
import pytest
from sqlalchemy import select

from threatwatch.cli import main as cli_main
from threatwatch.config import get_settings
from threatwatch.core import auth
from threatwatch.db import session_scope
from threatwatch.models import User

PW = "correct horse battery"


@pytest.fixture(autouse=True)
def _reset_throttle():
    auth.throttle.clear()
    yield
    auth.throttle.clear()


def make_user(username="alice", role="analyst", password=PW):
    with session_scope() as db:
        auth.create_user(db, username, password, role)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def login(client, username="alice", password=PW):
    """Sign in and, on success, attach the returned token to the client for subsequent requests."""
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    if r.status_code == 200:
        client.headers["Authorization"] = f"Bearer {r.json()['token']}"
    return r


def signed_out(client):
    client.headers.pop("Authorization", None)


# ---------------------------------------------------------------- core
def test_password_hashing_roundtrip():
    h = auth.hash_password(PW)
    assert h.startswith("scrypt$") and PW not in h
    assert auth.verify_password(PW, h)
    assert not auth.verify_password(PW + "x", h)
    assert not auth.verify_password(PW, "garbage")
    assert auth.hash_password(PW) != h  # salted


@pytest.mark.parametrize("username,password,msg", [
    ("bob", "short", "at least 10"),
    ("bob", "bob", "at least 10"),
    ("bobbobbobbob", "BobBobBobBob", "must not equal"),
    ("x", PW, "username"),
    ("has space", PW, "username"),
])
def test_create_user_validation(db, username, password, msg):
    with pytest.raises(auth.AuthError, match=msg):
        auth.create_user(db, username, password)


def test_duplicate_username_case_insensitive(db):
    auth.create_user(db, "Alice", PW)
    with pytest.raises(auth.AuthError, match="already exists"):
        auth.create_user(db, "alice", PW)


# ---------------------------------------------------------------- open mode & setup
def test_open_when_nothing_configured(client):
    assert client.get("/api/v1/assets").status_code == 200
    me = client.get("/api/v1/auth/me").json()
    assert me["mode"] == "open" and me["setup_required"] is True


def test_setup_creates_admin_then_locks(client):
    r = client.post("/api/v1/auth/setup", json={"username": "root", "password": PW})
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin"
    token = r.json()["token"]
    assert token and r.json()["token_type"] == "bearer" and r.json()["expires_in"] > 0
    me = client.get("/api/v1/auth/me", headers=bearer(token)).json()
    assert me["mode"] == "jwt" and me["user"]["username"] == "root"
    # second setup refused, and the API is no longer open to anonymous callers
    assert client.post("/api/v1/auth/setup", json={"username": "evil", "password": PW}).status_code == 409
    assert client.get("/api/v1/assets").status_code == 401


def test_setup_requires_api_key_when_configured(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cret")
    body = {"username": "root", "password": PW}
    assert client.post("/api/v1/auth/setup", json=body).status_code == 401
    r = client.post("/api/v1/auth/setup", json=body, headers={"X-API-Key": "s3cret"})
    assert r.status_code == 200 and r.json()["token"]


# ---------------------------------------------------------------- login / tokens
def test_login_returns_token_and_gates_the_api(client):
    make_user()
    assert client.get("/api/v1/assets").status_code == 401
    assert login(client, password="wrong password").status_code == 401
    r = login(client)
    assert r.status_code == 200 and r.json()["token_type"] == "bearer"
    assert "set-cookie" not in {k.lower() for k in r.headers}  # no cookies any more
    assert client.get("/api/v1/assets").status_code == 200
    me = client.get("/api/v1/auth/me").json()
    assert me["user"]["username"] == "alice" and me["mode"] == "jwt"


def test_logout_is_client_side(client):
    """Logout returns 204 but cannot revoke a stateless token; the client simply stops sending it."""
    make_user()
    login(client)
    assert client.post("/api/v1/auth/logout").status_code == 204
    signed_out(client)
    assert client.get("/api/v1/assets").status_code == 401


def test_token_accepted_as_query_param(client):
    """Plain-link downloads can't set an Authorization header, so ?access_token= is also accepted."""
    make_user()
    token = login(client).json()["token"]
    signed_out(client)
    assert client.get("/api/v1/assets", params={"access_token": token}).status_code == 200
    assert client.get("/api/v1/assets").status_code == 401


def test_token_is_a_signed_jwt(client):
    make_user()
    claims = jwt.decode(login(client).json()["token"], auth._signing_secret(),
                        algorithms=[get_settings().jwt_algorithm])
    assert claims["username"] == "alice" and claims["role"] == "analyst" and claims["exp"] > claims["iat"]


def test_expired_token_rejected(client):
    make_user()
    stale = jwt.encode({"sub": "1", "role": "analyst", "iat": int(time.time()) - 100, "exp": int(time.time()) - 50},
                       auth._signing_secret(), algorithm=get_settings().jwt_algorithm)
    assert auth.decode_access_token(stale) is None
    assert client.get("/api/v1/assets", headers=bearer(stale)).status_code == 401


def test_tampered_token_rejected(client):
    make_user()
    token = login(client).json()["token"]
    forged = token[:-3] + ("aaa" if token[-3:] != "aaa" else "bbb")
    signed_out(client)
    assert client.get("/api/v1/assets", headers=bearer(forged)).status_code == 401


def test_token_signed_with_other_key_rejected(client):
    make_user()
    alien = jwt.encode({"sub": "1", "role": "admin", "exp": int(time.time()) + 3600}, "not-the-secret",
                       algorithm="HS256")
    assert client.get("/api/v1/assets", headers=bearer(alien)).status_code == 401


def test_disabled_user_cannot_sign_in(client):
    make_user()
    with session_scope() as db:
        db.scalar(select(User)).disabled = True
    assert login(client).status_code == 401


def test_login_throttled(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "login_max_failures", 3)
    make_user()
    for _ in range(3):
        assert login(client, password="wrong password").status_code == 401
    r = login(client)  # even the right password is refused while locked
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


def test_unknown_user_same_error(client):
    make_user()
    a = login(client, username="nobody", password=PW)
    b = login(client, password="wrong password")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


# ---------------------------------------------------------------- roles (no CSRF with bearer tokens)
def test_token_writes_need_no_csrf_header(client):
    make_user()
    login(client)
    assert client.post("/api/v1/assets", json={"type": "domain", "value": "example.com"}).status_code in (200, 201)


def test_api_key_writes_work(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cret")
    r = client.post("/api/v1/assets", json={"type": "domain", "value": "example.org"}, headers={"X-API-Key": "s3cret"})
    assert r.status_code in (200, 201)


def test_viewer_is_read_only(client):
    make_user("vera", role="viewer")
    login(client, "vera")
    assert client.get("/api/v1/assets").status_code == 200
    r = client.post("/api/v1/assets", json={"type": "domain", "value": "example.com"})
    assert r.status_code == 403 and "read-only" in r.json()["detail"]
    # ...but can still change their own password
    r = client.post("/api/v1/auth/password", json={"current_password": PW, "new_password": "another long pass"})
    assert r.status_code == 200 and r.json()["token"]


def test_user_management_requires_admin(client):
    make_user("alice", role="analyst")
    login(client)
    assert client.get("/api/v1/users").status_code == 403


def test_admin_manages_users(client):
    make_user("root", role="admin")
    login(client, "root")
    r = client.post("/api/v1/users", json={"username": "bob", "password": PW, "role": "viewer"})
    assert r.status_code == 201
    bob = r.json()["id"]
    assert [u["username"] for u in client.get("/api/v1/users").json()["items"]] == ["bob", "root"]
    assert client.patch(f"/api/v1/users/{bob}", json={"role": "analyst"}).json()["role"] == "analyst"
    assert client.patch(f"/api/v1/users/{bob}", json={"password": "short"}).status_code == 422
    assert client.delete(f"/api/v1/users/{bob}").status_code == 204


def test_last_admin_protected(client):
    make_user("root", role="admin")
    login(client, "root")
    root = client.get("/api/v1/auth/me").json()["user"]["id"]
    assert client.patch(f"/api/v1/users/{root}", json={"role": "viewer"}).status_code == 409
    assert client.patch(f"/api/v1/users/{root}", json={"disabled": True}).status_code == 409
    assert client.delete(f"/api/v1/users/{root}").status_code == 409


def test_api_key_counts_as_admin(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cret")
    make_user()
    assert client.get("/api/v1/users", headers={"X-API-Key": "s3cret"}).status_code == 200


# ---------------------------------------------------------------- password change
def test_password_change_issues_new_token(client):
    """Stateless trade-off: changing the password hands back a fresh token, but tokens issued earlier
    (e.g. on another device) keep working until they expire - a password change cannot revoke them."""
    from fastapi.testclient import TestClient

    make_user()
    other = TestClient(client.app)
    other_token = other.post("/api/v1/auth/login", json={"username": "alice", "password": PW}).json()["token"]
    login(client)

    assert client.post("/api/v1/auth/password",
                       json={"current_password": "nope nope nope", "new_password": "a brand new pass"}).status_code == 403
    r = client.post("/api/v1/auth/password", json={"current_password": PW, "new_password": "a brand new pass"})
    assert r.status_code == 200 and r.json()["token"]
    client.headers["Authorization"] = f"Bearer {r.json()['token']}"
    assert client.get("/api/v1/assets").status_code == 200  # new token works

    # the other device's token is still valid (documented stateless behaviour)
    assert other.get("/api/v1/assets", headers=bearer(other_token)).status_code == 200
    # the old password no longer authenticates a fresh sign-in
    signed_out(client)
    assert login(client).status_code == 401
    assert login(client, password="a brand new pass").status_code == 200


# ---------------------------------------------------------------- CLI
def test_cli_user_commands(db, monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(PW + "\n"))
    cli_main(["user", "add", "Root", "--password-stdin"])
    assert "created admin 'root'" in capsys.readouterr().out  # first user defaults to admin
    monkeypatch.setattr("sys.stdin", io.StringIO(PW + "\n"))
    cli_main(["user", "add", "eve", "--password-stdin"])
    assert "created analyst 'eve'" in capsys.readouterr().out
    cli_main(["user", "role", "eve", "--role", "viewer"])
    cli_main(["user", "list"])
    out = capsys.readouterr().out
    assert "root" in out and "viewer" in out
    with pytest.raises(SystemExit, match="last active admin"):
        cli_main(["user", "delete", "root"])
