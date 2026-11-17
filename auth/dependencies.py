"""FastAPI dependencies for auth-protected routes."""

from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth.security import decode_token
from db.connection import get_dict_cursor

_bearer = HTTPBearer(auto_error=False)


class CurrentUser:
    __slots__ = ("id", "email", "role")

    def __init__(self, id: int, email: str, role: str):
        self.id = id
        self.email = email
        self.role = role


def _load_user(user_id: int) -> Optional[CurrentUser]:
    with get_dict_cursor() as cur:
        cur.execute(
            "SELECT id, email, role FROM users WHERE id = %s",
            (user_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return CurrentUser(id=row["id"], email=row["email"], role=row["role"])


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> CurrentUser:
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(creds.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token: missing subject",
        )
    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token: subject is not an integer",
        )
    user = _load_user(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
        )
    return user


def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return user
