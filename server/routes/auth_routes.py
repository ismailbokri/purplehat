"""POST /auth/register, POST /auth/login, GET /auth/me.

First user registered is promoted to admin. All subsequent registrations
default to role='user'.
"""

import logging
import re
from typing import Optional

import psycopg2
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from auth.dependencies import CurrentUser, get_current_user
from auth.security import create_access_token, hash_password, verify_password
from db.connection import get_dict_cursor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Models ────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:    EmailStr
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user_id:      int
    email:        str
    role:         str


class MeResponse(BaseModel):
    id:    int
    email: str
    role:  str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse)
def register(payload: RegisterRequest) -> TokenResponse:
    email = payload.email.lower().strip()
    pw_hash = hash_password(payload.password)

    try:
        with get_dict_cursor() as cur:
            # First registered user → admin. Counting + insert in same txn.
            cur.execute("SELECT COUNT(*) AS n FROM users")
            user_count = int(cur.fetchone()["n"])
            role = "admin" if user_count == 0 else "user"

            cur.execute(
                """
                INSERT INTO users (email, password_hash, role)
                VALUES (%s, %s, %s)
                RETURNING id, email, role
                """,
                (email, pw_hash, role),
            )
            row = cur.fetchone()
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    token = create_access_token(user_id=row["id"], email=row["email"], role=row["role"])
    return TokenResponse(
        access_token=token,
        user_id=row["id"],
        email=row["email"],
        role=row["role"],
    )


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    email = payload.email.lower().strip()
    with get_dict_cursor() as cur:
        cur.execute(
            "SELECT id, email, role, password_hash FROM users WHERE email = %s",
            (email,),
        )
        row = cur.fetchone()

    if row is None or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = create_access_token(user_id=row["id"], email=row["email"], role=row["role"])
    return TokenResponse(
        access_token=token,
        user_id=row["id"],
        email=row["email"],
        role=row["role"],
    )


@router.get("/me", response_model=MeResponse)
def me(user: CurrentUser = Depends(get_current_user)) -> MeResponse:
    return MeResponse(id=user.id, email=user.email, role=user.role)
