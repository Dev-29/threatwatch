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
    CSRF_HEADER,
    api_key_valid,
    has_csrf_header,
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


def _require_csrf(request: Request) -> None:
    if not has_csrf_header(request):
        raise HTTPException(403, f"missing {CSRF_HEADER} header")


def _set_cookie(request: Request, response: Response, token: str) -> None:
    mode = get_settings().session_cookie_secure.strip().lower()
    secure = request.url.scheme == "https" if mode == "auto" else mode in ("1", "true", "yes", "on")
    response.set_cookie(auth.COOKIE_NAME, token, max_age=int(get_settings().session_max_days * 86400),
                        httponly=True, secure=secure, samesite="strict", path="/")


def _start_session(request: Request, response: Response, db: Session, user: User) -> None:
    token = auth.create_session(db, user, _client_ip(request), request.headers.get("user-agent"))
    _set_cookie(request, response, token)


def _bad_request(e: auth.AuthError):
    return HTTPException(422, str(e))


# ---------------------------------------------------------------- session endpoints
@router.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    """Who is signed in, and whether the first admin account still needs to be created."""
    mode, user = identify(request, db)
    s = get_settings()
    return {"authenticated": mode is not None, "mode": mode, "user": user_json(user) if user else None,
            "setup_required": auth.user_count(db) == 0, "api_key_configured": bool(s.api_key)}


@router.post("/login")
def login(body: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    _require_csrf(request)
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
    auth.revoke_session(db, request.cookies.get(auth.COOKIE_NAME))  # no session fixation
    _start_session(request, response, db, user)
    return {"user": user_json(user)}


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    _require_csrf(request)
    auth.revoke_session(db, request.cookies.get(auth.COOKIE_NAME))
    response.delete_cookie(auth.COOKIE_NAME, path="/")


@router.post("/setup")
def setup(body: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    """Create the first admin account. Only possible while no users exist; needs the API key if one is set."""
    _require_csrf(request)
    if auth.user_count(db) > 0:
        raise HTTPException(409, "setup already completed; sign in instead")
    if get_settings().api_key and not api_key_valid(request):
        raise HTTPException(401, "TW_API_KEY is set: supply it to create the first admin")
    try:
        user = auth.create_user(db, body.username, body.password, role="admin")
    except auth.AuthError as e:
        raise _bad_request(e) from e
    _start_session(request, response, db, user)
    return {"user": user_json(user)}


@router.post("/password")
def change_password(body: PasswordChange, request: Request, response: Response, db: Session = Depends(get_db)):
    """Change your own password. Signs out every other session of this user."""
    _require_csrf(request)
    mode, user = identify(request, db)
    if mode != "session":
        raise HTTPException(401, "sign in to change your password")
    if not auth.verify_password(body.current_password, user.password_hash):
        raise HTTPException(403, "current password is incorrect")
    try:
        auth.set_password(db, user, body.new_password)  # revokes all sessions, including this one
    except auth.AuthError as e:
        raise _bad_request(e) from e
    _start_session(request, response, db, user)
    return {"ok": True}


# ---------------------------------------------------------------- user management (admin)
def _get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    return user


def _is_self(request: Request, user: User) -> bool:
    me_ = getattr(request.state, "user", None)
    return me_ is not None and me_.id == user.id


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
        if body.disabled:
            auth.revoke_user_sessions(db, user.id)
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
