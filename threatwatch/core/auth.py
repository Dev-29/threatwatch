"""User accounts: password hashing, browser sessions and login throttling.

* Passwords are hashed with scrypt (stdlib, memory-hard) and a per-user random salt.
* Session tokens are 256-bit random values. The browser holds the token in an HttpOnly cookie;
  the database only stores its SHA-256, so a copy of the database cannot be replayed as a login.
* Sessions slide forward on use (``TW_SESSION_IDLE_HOURS``) up to an absolute cap
  (``TW_SESSION_MAX_DAYS``), and are revoked on logout, password change, role change or disable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import User, UserSession, utcnow

ROLES = ("admin", "analyst", "viewer")
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,63}$")
MIN_PASSWORD_LEN = 10
COOKIE_NAME = "tw_session"

# scrypt cost: N=2^15, r=8, p=1 -> ~32 MiB and ~50-100 ms per hash.
_N, _R, _P, _DKLEN = 2**15, 8, 1, 32
_MAXMEM = 64 * 1024 * 1024


class AuthError(ValueError):
    """Invalid input for an account operation (shown to the user)."""


# ---------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN, maxmem=_MAXMEM)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${_N}${_R}${_P}${b64(salt)}${b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(dk)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(expected), maxmem=_MAXMEM)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


# Verified against when the username does not exist, so response time does not reveal valid usernames.
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def check_password_policy(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise AuthError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if len(password) > 1024:
        raise AuthError("password is too long")
    if username and password.lower() == username.lower():
        raise AuthError("password must not equal the username")


def normalize_username(username: str) -> str:
    u = (username or "").strip().lower()
    if not USERNAME_RE.match(u):
        raise AuthError("username must be 2-64 characters: letters, digits, '.', '_', '-', '@'")
    return u


# ---------------------------------------------------------------- users
def user_count(db: Session) -> int:
    return db.scalar(select(func.count(User.id))) or 0


def active_admin_count(db: Session) -> int:
    return db.scalar(select(func.count(User.id)).where(User.role == "admin", User.disabled.is_(False))) or 0


def create_user(db: Session, username: str, password: str, role: str = "analyst") -> User:
    username = normalize_username(username)
    if role not in ROLES:
        raise AuthError(f"role must be one of {', '.join(ROLES)}")
    check_password_policy(password, username)
    if db.scalar(select(User.id).where(User.username == username)):
        raise AuthError(f"user '{username}' already exists")
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()
    return user


def set_password(db: Session, user: User, password: str) -> None:
    check_password_policy(password, user.username)
    user.password_hash = hash_password(password)
    user.password_changed_at = utcnow()
    revoke_user_sessions(db, user.id)


def authenticate(db: Session, username: str, password: str) -> User | None:
    try:
        username = normalize_username(username)
    except AuthError:
        verify_password(password, _DUMMY_HASH)
        return None
    user = db.scalar(select(User).where(User.username == username))
    if user is None or user.disabled:
        verify_password(password, _DUMMY_HASH)
        return None
    return user if verify_password(password, user.password_hash) else None


# ---------------------------------------------------------------- sessions
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User, ip: str | None = None, user_agent: str | None = None) -> str:
    s = get_settings()
    now = utcnow()
    db.execute(delete(UserSession).where(UserSession.expires_at < now))  # opportunistic cleanup
    token = secrets.token_urlsafe(32)
    db.add(UserSession(token_hash=_token_hash(token), user_id=user.id, created_at=now, last_seen_at=now,
                       expires_at=now + timedelta(hours=s.session_idle_hours),
                       ip=(ip or "")[:64] or None, user_agent=(user_agent or "")[:255] or None))
    user.last_login_at = now
    db.flush()
    return token


def resolve_session(db: Session, token: str | None) -> User | None:
    """Return the signed-in user for a cookie token, sliding the expiry forward. None if invalid/expired."""
    if not token or len(token) > 128:
        return None
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == _token_hash(token)))
    if sess is None:
        return None
    s = get_settings()
    now = utcnow()
    hard_limit = sess.created_at + timedelta(days=s.session_max_days)
    if sess.expires_at <= now or hard_limit <= now or sess.user.disabled:
        db.delete(sess)
        return None
    if (now - sess.last_seen_at).total_seconds() > 60:  # avoid a write on every request
        sess.last_seen_at = now
        sess.expires_at = min(now + timedelta(hours=s.session_idle_hours), hard_limit)
    return sess.user


def revoke_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(UserSession).where(UserSession.token_hash == _token_hash(token)))


def revoke_user_sessions(db: Session, user_id: int) -> None:
    db.execute(delete(UserSession).where(UserSession.user_id == user_id))


# ---------------------------------------------------------------- login throttling
class LoginThrottle:
    """In-memory sliding window of failed logins per (client IP, username)."""

    WINDOW = 15 * 60

    def __init__(self) -> None:
        self._fails: dict[tuple[str, str], list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: tuple[str, str], now: float) -> list[float]:
        hits = [t for t in self._fails.get(key, []) if now - t < self.WINDOW]
        if hits:
            self._fails[key] = hits
        else:
            self._fails.pop(key, None)
        return hits

    def retry_after(self, ip: str, username: str) -> int:
        """Seconds until another attempt is allowed (0 = allowed now)."""
        now = time.monotonic()
        with self._lock:
            hits = self._recent((ip, username.lower()), now)
            if len(hits) < get_settings().login_max_failures:
                return 0
            return max(1, int(self.WINDOW - (now - hits[0])))

    def fail(self, ip: str, username: str) -> None:
        now = time.monotonic()
        with self._lock:
            if len(self._fails) > 10_000:  # bound memory under a spray attack
                for k in list(self._fails):
                    self._recent(k, now)
            self._fails.setdefault((ip, username.lower()), []).append(now)

    def reset(self, ip: str, username: str) -> None:
        with self._lock:
            self._fails.pop((ip, username.lower()), None)

    def clear(self) -> None:
        with self._lock:
            self._fails.clear()


throttle = LoginThrottle()
