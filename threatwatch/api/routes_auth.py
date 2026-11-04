"""Sign-in, first-run setup, password change and user management."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..core import auth
from ..db import get_db
from ..models import User
from .common import (
    api_key_valid,
    identify,
    require_admin,
    require_auth,
    user_json,
)

# /auth/* handles its own authentication (login must work while signed out).
router = APIRouter(prefix="/auth", tags=["auth"])
# /users/* is mounted behind require_auth and additionally needs the admin role.
users = APIRouter(prefix="/users", tags=["auth"], dependencies=[Depends(require_admin)])

Role = Literal["admin", "analyst", "viewer"]


class Credentials(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=1024)


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(max_length=1024)


class NewUser(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=1024)
    role: Role = "analyst"


class UserPatch(BaseModel):
    role: Role | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, max_length=1024)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _token_response(db: Session, user: User) -> dict:
    """Issue a fresh JWT and the standard token envelope, with the user record alongside for convenience."""
    token, expires_in = auth.create_access_token(db, user)
    return {"token": token, "token_type": "bearer", "expires_in": expires_in, "user": user_json(user)}


def _current_user(request: Request, db: Session) -> User | None:
    """The signed-in user, loaded from the JWT's subject claim. None for API-key / open / anonymous callers."""
    mode, claims = identify(request, db)
    if mode != "jwt" or not claims:
        return None
    return db.get(User, int(claims["sub"]))


def _bad_request(e: auth.AuthError):
    return HTTPException(422, str(e))


# ---------------------------------------------------------------- session endpoints
@router.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    """Who is signed in, and whether the first admin account still needs to be created."""
    mode, _ = identify(request, db)
    user = _current_user(request, db) if mode == "jwt" else None
    s = get_settings()
    return {"authenticated": mode is not None, "mode": mode, "user": user_json(user) if user else None,
            "setup_required": auth.user_count(db) == 0, "api_key_configured": bool(s.api_key)}


@router.post("/login")
def login(body: Credentials, request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    wait = auth.throttle.retry_after(ip, body.username)
    if wait:
        raise HTTPException(429, f"too many failed sign-in attempts; try again in {wait // 60 + 1} min",
                            headers={"Retry-After": str(wait)})
    user = auth.authenticate(db, body.username, body.password)
    if user is None:
        auth.throttle.fail(ip, body.username)
        raise HTTPException(401, "invalid username or password")
    auth.throttle.reset(ip, body.username)
    return _token_response(db, user)


@router.post("/logout", status_code=204)
def logout():
    """No-op for stateless tokens: the client simply discards its JWT. Provided for API symmetry."""
    return Response(status_code=204)


@router.post("/setup")
def setup(body: Credentials, request: Request, db: Session = Depends(get_db)):
    """Create the first admin account. Only possible while no users exist; needs the API key if one is set."""
    if auth.user_count(db) > 0:
        raise HTTPException(409, "setup already completed; sign in instead")
    if get_settings().api_key and not api_key_valid(request):
        raise HTTPException(401, "TW_API_KEY is set: supply it to create the first admin")
    try:
        user = auth.create_user(db, body.username, body.password, role="admin")
    except auth.AuthError as e:
        raise _bad_request(e) from e
    return _token_response(db, user)


@router.post("/password")
def change_password(body: PasswordChange, request: Request, db: Session = Depends(get_db)):
    """Change your own password and get a fresh token.

    Note: because tokens are stateless, JWTs issued earlier (including on other devices) stay valid until
    they expire - a password change cannot forcibly sign them out. Keep TW_JWT_EXPIRY_MINUTES short if
    that matters to you.
    """
    user = _current_user(request, db)
    if user is None:
        raise HTTPException(401, "sign in to change your password")
    if not auth.verify_password(body.current_password, user.password_hash):
        raise HTTPException(403, "current password is incorrect")
    try:
        auth.set_password(db, user, body.new_password)
    except auth.AuthError as e:
        raise _bad_request(e) from e
    return {"ok": True, **_token_response(db, user)}


# ---------------------------------------------------------------- user management (admin)
def _get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    return user


def _is_self(request: Request, user: User) -> bool:
    uid = getattr(request.state, "user_id", None)
    return uid is not None and uid == user.id


@users.get("")
def list_users(db: Session = Depends(get_db)):
    return {"items": [user_json(u) for u in db.scalars(select(User).order_by(User.username))]}


@users.post("", status_code=201)
def add_user(body: NewUser, db: Session = Depends(get_db)):
    try:
        return user_json(auth.create_user(db, body.username, body.password, body.role))
    except auth.AuthError as e:
        raise _bad_request(e) from e


@users.patch("/{user_id}")
def update_user(user_id: int, body: UserPatch, request: Request, db: Session = Depends(get_db)):
    user = _get_user(db, user_id)
    loses_admin = user.role == "admin" and not user.disabled and (
        (body.role is not None and body.role != "admin") or body.disabled is True)
    if loses_admin and auth.active_admin_count(db) <= 1:
        raise HTTPException(409, "cannot demote or disable the last active admin")
    if body.disabled is True and _is_self(request, user):
        raise HTTPException(409, "you cannot disable your own account")
    if body.role is not None:
        user.role = body.role
    if body.disabled is not None:
        user.disabled = body.disabled
        # Disabling blocks new sign-ins, but any JWT already issued to this user keeps working until it
        # expires - stateless tokens cannot be revoked server-side.
    if body.password:
        try:
            auth.set_password(db, user, body.password)
        except auth.AuthError as e:
            raise _bad_request(e) from e
    return user_json(user)


@users.delete("/{user_id}", status_code=204)
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    user = _get_user(db, user_id)
    if _is_self(request, user):
        raise HTTPException(409, "you cannot delete your own account")
    if user.role == "admin" and not user.disabled and auth.active_admin_count(db) <= 1:
        raise HTTPException(409, "cannot delete the last active admin")
    db.delete(user)
    return Response(status_code=204)


__all__ = ["router", "users", "require_auth"]
