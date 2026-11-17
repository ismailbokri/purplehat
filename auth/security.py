"""Password hashing (bcrypt) and JWT issuance/decoding.

JWT_SECRET is read from the .env file. A safe default is used in development
with a clear warning — set JWT_SECRET to a strong random value in production.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
from dotenv import load_dotenv
from jose import JWTError, jwt

load_dotenv()

logger = logging.getLogger(__name__)

_JWT_ALGORITHM = "HS256"
_JWT_TTL_HOURS = 24

_DEV_DEFAULT_SECRET = "dev-only-secret-change-me-in-production"
_jwt_secret = os.getenv("JWT_SECRET", "").strip()
if not _jwt_secret:
    _jwt_secret = _DEV_DEFAULT_SECRET
    logger.warning(
        "[auth] JWT_SECRET env var is not set — using dev default. "
        "Add JWT_SECRET=<random-64-chars> to your .env in production."
    )


# ── Password hashing ─────────────────────────────────────────────────────────

# bcrypt has a hard 72-byte input limit. Truncate silently on hash so the user
# never sees a ValueError; verify must apply the same truncation to match.
_BCRYPT_MAX_BYTES = 72


def _to_bytes(plain: str) -> bytes:
    raw = plain.encode("utf-8")
    return raw[:_BCRYPT_MAX_BYTES]


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_to_bytes(plain), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_to_bytes(plain), hashed.encode("utf-8"))
    except Exception:
        return False


# ── JWT ──────────────────────────────────────────────────────────────────────

def create_access_token(*, user_id: int, email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub":   str(user_id),
        "email": email,
        "role":  role,
        "iat":   int(now.timestamp()),
        "exp":   int((now + timedelta(hours=_JWT_TTL_HOURS)).timestamp()),
        "jti":   secrets.token_hex(8),
    }
    return jwt.encode(payload, _jwt_secret, algorithm=_JWT_ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, _jwt_secret, algorithms=[_JWT_ALGORITHM])
    except JWTError as exc:
        logger.debug("[auth] invalid JWT: %s", exc)
        return None
