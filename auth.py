"""Authentication utilities including password hashing and JWT helpers."""
from __future__ import annotations

import os
import asyncio
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from db import get_user_by_id


class TokenBlacklist:
    """In-memory token blacklist with automatic expiration cleanup."""

    def __init__(self) -> None:
        self._tokens: dict[str, datetime] = {}
        self._lock = asyncio.Lock()

    async def add(self, token: str, *, expires_at: datetime) -> None:
        async with self._lock:
            self._purge_locked()
            self._tokens[token] = expires_at

    async def contains(self, token: str) -> bool:
        async with self._lock:
            self._purge_locked()
            return token in self._tokens

    def _purge_locked(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [stored for stored, expiry in self._tokens.items() if expiry <= now]
        for token in expired:
            self._tokens.pop(token, None)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRES_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", "30"))


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with a random salt."""
    # bcrypt.gensalt() automatically generates a secure salt for every password hash.
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


class TokenType(StrEnum):
    """Enumeration describing supported token types."""

    ACCESS = "access"


def create_access_token(*, user_id: str, email: str, token_type: TokenType = TokenType.ACCESS) -> str:
    """Create a signed JWT containing user identity claims."""
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    expire_at = datetime.now(timezone.utc) + expires_delta
    # Encode user claims and expiration timestamp to produce the JWT.
    payload = {
        "sub": str(user_id),
        "email": email,
        "type": token_type.value,
        "exp": expire_at,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode a JWT and return its payload."""
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])


http_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer),
) -> dict[str, Any]:
    """FastAPI dependency that resolves the authenticated user."""
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")

    token = credentials.credentials
    token_blacklist: TokenBlacklist | None = getattr(request.app.state, "token_blacklist", None)
    if token_blacklist is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Auth backend unavailable")

    # Reject any token that has been explicitly invalidated during logout.
    if await token_blacklist.contains(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError as exc:  # type: ignore[attr-defined]
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired") from exc
    except jwt.InvalidTokenError as exc:  # type: ignore[attr-defined]
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await get_user_by_id(str(user_id))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return user
