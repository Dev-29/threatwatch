"""User accounts: password hashing, stateless JWT access tokens and login throttling.

* Passwords are hashed with scrypt (stdlib, memory-hard) and a per-user random salt.
* Authentication is a stateless JSON Web Token (HS256). On sign-in the client receives a signed JWT
  carrying its user id, username and role, and sends it as ``Authorization: Bearer <token>`` thereafter.
  The token is verified by signature and expiry alone - there is no server-side session store.

  Trade-off of statelessness: a token is valid until its ``exp`` no matter what happens server-side.
  Logout is therefore client-side (the client discards the token), and a password change, role change
  or account-disable does *not* invalidate tokens already issued - they keep working until they expire
  (``TW_JWT_EXPIRY_MINUTES``). Keep the expiry short if that matters for your threat model.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from pathlib import Path

import jwt  # PyJWT

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import User, utcnow

ROLES = ("admin", "analyst", "viewer")
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,63}$")
MIN_PASSWORD_LEN = 10
_JWT_LEEWAY = 10  # seconds of clock-skew tolerance on exp/iat
_MAX_TOKEN_LEN = 4096

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
    # Stateless tokens cannot be revoked, so JWTs issued before this change stay valid until they expire.
    # The caller should hand the user a fresh token; older ones age out on their own.


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


# ---------------------------------------------------------------- JWT access tokens
def _signing_secret() -> str:
    """HS256 signing key. Uses ``TW_JWT_SECRET`` if set, otherwise a persistent random key stored under
    the data directory so tokens survive restarts without requiring any configuration."""
    s = get_settings()
    if s.jwt_secret:
        return s.jwt_secret
    path = Path(s.data_dir) / "jwt_secret.key"
    try:
        secret = path.read_text().strip()
        if secret:
            return secret
    except OSError:
        pass
    secret = secrets.token_urlsafe(48)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secret)
        path.chmod(0o600)
    except OSError:
        pass  # read-only data dir: fall back to an in-process key (tokens won't survive a restart)
    return secret


def create_access_token(db: Session, user: User) -> tuple[str, int]:
    """Mint a signed JWT for ``user`` and record the login time. Returns ``(token, expires_in_seconds)``."""
    s = get_settings()
    expires_in = max(60, s.jwt_expiry_minutes * 60)
    now = int(time.time())
    payload = {"sub": str(user.id), "username": user.username, "role": user.role,
               "iat": now, "nbf": now, "exp": now + expires_in}
    token = jwt.encode(payload, _signing_secret(), algorithm=s.jwt_algorithm)
    user.last_login_at = utcnow()
    db.flush()
    return token, expires_in


def decode_access_token(token: str | None) -> dict | None:
    """Verify a bearer token's signature and expiry. Returns its claims, or None if invalid/expired."""
    if not token or len(token) > _MAX_TOKEN_LEN:
        return None
    try:
        return jwt.decode(token, _signing_secret(), algorithms=[get_settings().jwt_algorithm],
                          leeway=_JWT_LEEWAY, options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        return None


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
