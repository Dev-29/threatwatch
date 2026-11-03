"""User accounts, browser sessions, roles, CSRF and login throttling."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from threatwatch.cli import main as cli_main
from threatwatch.config import get_settings
from threatwatch.core import auth
from threatwatch.db import session_scope
from threatwatch.models import User, UserSession

H = {"X-Requested-With": "ThreatWatch"}
PW = "correct horse battery"


@pytest.fixture(autouse=True)
def _reset_throttle():
    auth.throttle.clear()
    yield
    auth.throttle.clear()


def make_user(username="alice", role="analyst", password=PW):
    with session_scope() as db:
        auth.create_user(db, username, password, role)


def login(client, username="alice", password=PW):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password}, headers=H)


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
    r = client.post("/api/v1/auth/setup", json={"username": "root", "password": PW}, headers=H)
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin"
    assert client.get("/api/v1/auth/me").json()["mode"] == "session"  # signed in by setup
    # second setup refused, and the API is no longer open to anonymous callers
    assert client.post("/api/v1/auth/setup", json={"username": "evil", "password": PW}, headers=H).status_code == 409
    client.cookies.clear()
    assert client.get("/api/v1/assets").status_code == 401


def test_setup_requires_api_key_when_configured(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cret")
    body = {"username": "root", "password": PW}
    assert client.post("/api/v1/auth/setup", json=body, headers=H).status_code == 401
    r = client.post("/api/v1/auth/setup", json=body, headers={**H, "X-API-Key": "s3cret"})
    assert r.status_code == 200


def test_setup_requires_csrf_header(client):
    assert client.post("/api/v1/auth/setup", json={"username": "root", "password": PW}).status_code == 403


# ---------------------------------------------------------------- login / sessions
def test_login_logout_flow(client):
    make_user()
    assert client.get("/api/v1/assets").status_code == 401
    assert login(client, password="wrong password").status_code == 401
    r = login(client)
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and auth.COOKIE_NAME in cookie
    assert client.get("/api/v1/assets").status_code == 200
    me = client.get("/api/v1/auth/me").json()
    assert me["user"]["username"] == "alice" and me["mode"] == "session"
    assert client.post("/api/v1/auth/logout", headers=H).status_code == 204
    assert client.get("/api/v1/assets").status_code == 401


def test_session_token_stored_hashed(client):
    make_user()
    login(client)
    token = client.cookies.get(auth.COOKIE_NAME)
    with session_scope() as db:
        hashes = db.scalars(select(UserSession.token_hash)).all()
    assert token and token not in hashes and len(hashes) == 1


def test_expired_session_rejected(client):
    make_user()
    login(client)
    with session_scope() as db:
        for s in db.scalars(select(UserSession)):
            s.expires_at = s.expires_at - timedelta(days=30)
    assert client.get("/api/v1/assets").status_code == 401


def test_absolute_session_lifetime(client):
    make_user()
    login(client)
    with session_scope() as db:
        for s in db.scalars(select(UserSession)):
            s.created_at = s.created_at - timedelta(days=get_settings().session_max_days + 1)
    assert client.get("/api/v1/assets").status_code == 401


def test_disabled_user_cannot_sign_in_or_continue(client):
    make_user()
    login(client)
    with session_scope() as db:
        db.scalar(select(User)).disabled = True
    assert client.get("/api/v1/assets").status_code == 401
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


# ---------------------------------------------------------------- CSRF and roles
def test_cookie_writes_need_csrf_header(client):
    make_user()
    login(client)
    body = {"type": "domain", "value": "example.com"}
    assert client.post("/api/v1/assets", json=body).status_code == 403
    assert client.post("/api/v1/assets", json=body, headers=H).status_code in (200, 201)


def test_api_key_writes_do_not_need_csrf_header(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cret")
    r = client.post("/api/v1/assets", json={"type": "domain", "value": "example.org"}, headers={"X-API-Key": "s3cret"})
    assert r.status_code in (200, 201)


def test_viewer_is_read_only(client):
    make_user("vera", role="viewer")
    login(client, "vera")
    assert client.get("/api/v1/assets").status_code == 200
    r = client.post("/api/v1/assets", json={"type": "domain", "value": "example.com"}, headers=H)
    assert r.status_code == 403 and "read-only" in r.json()["detail"]
    # ...but can still change their own password
    r = client.post("/api/v1/auth/password", json={"current_password": PW, "new_password": "another long pass"}, headers=H)
    assert r.status_code == 200


def test_user_management_requires_admin(client):
    make_user("alice", role="analyst")
    login(client)
    assert client.get("/api/v1/users").status_code == 403


def test_admin_manages_users(client):
    make_user("root", role="admin")
    login(client, "root")
    r = client.post("/api/v1/users", json={"username": "bob", "password": PW, "role": "viewer"}, headers=H)
    assert r.status_code == 201
    bob = r.json()["id"]
    assert [u["username"] for u in client.get("/api/v1/users").json()["items"]] == ["bob", "root"]
    assert client.patch(f"/api/v1/users/{bob}", json={"role": "analyst"}, headers=H).json()["role"] == "analyst"
    assert client.patch(f"/api/v1/users/{bob}", json={"password": "short"}, headers=H).status_code == 422
    assert client.delete(f"/api/v1/users/{bob}", headers=H).status_code == 204


def test_last_admin_protected(client):
    make_user("root", role="admin")
    login(client, "root")
    root = client.get("/api/v1/auth/me").json()["user"]["id"]
    assert client.patch(f"/api/v1/users/{root}", json={"role": "viewer"}, headers=H).status_code == 409
    assert client.patch(f"/api/v1/users/{root}", json={"disabled": True}, headers=H).status_code == 409
    assert client.delete(f"/api/v1/users/{root}", headers=H).status_code == 409


def test_api_key_counts_as_admin(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cret")
    make_user()
    assert client.get("/api/v1/users", headers={"X-API-Key": "s3cret"}).status_code == 200


# ---------------------------------------------------------------- password change
def test_password_change_revokes_other_sessions(client):
    from fastapi.testclient import TestClient

    make_user()
    other = TestClient(client.app)
    login(other)
    login(client)
    r = client.post("/api/v1/auth/password", json={"current_password": "nope nope nope", "new_password": "a brand new pass"}, headers=H)
    assert r.status_code == 403
    r = client.post("/api/v1/auth/password", json={"current_password": PW, "new_password": "a brand new pass"}, headers=H)
    assert r.status_code == 200
    assert client.get("/api/v1/assets").status_code == 200  # this browser gets a fresh session
    assert other.get("/api/v1/assets").status_code == 401  # the other one is signed out
    client.cookies.clear()
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
