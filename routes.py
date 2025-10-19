"""API route definitions for authentication flows."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from auth import (
    ACCESS_TOKEN_EXPIRES_MINUTES,
    TokenType,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from db import create_user, get_user_by_email
from rate_limiter import global_rate_limit

api_router = APIRouter()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class UserResponse(BaseModel):
    id: str
    email: EmailStr


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = Field(default="bearer")
    expires_in: int


class MessageResponse(BaseModel):
    detail: str


@api_router.post("/register", response_model=UserResponse, responses={400: {"model": MessageResponse}})
@global_rate_limit
async def register(request: Request, payload: RegisterRequest) -> UserResponse:  # noqa: ARG001
    """Register a new user and persist it to Supabase."""
    existing_user = await get_user_by_email(payload.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    hashed_password = hash_password(payload.password)
    # Persist the new user record with hashed password stored securely in Supabase.
    user = await create_user(email=payload.email, hashed_password=hashed_password)
    return UserResponse(id=str(user["id"]), email=user["email"])


@api_router.post("/login", response_model=TokenResponse, responses={401: {"model": MessageResponse}})
@global_rate_limit
async def login(request: Request, payload: LoginRequest) -> TokenResponse:  # noqa: ARG001
    """Authenticate a user and return a signed JWT access token."""
    user = await get_user_by_email(payload.email)
    if user is None or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(user_id=str(user["id"]), email=user["email"], token_type=TokenType.ACCESS)
    expires_in = int(timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES).total_seconds())
    # Return JWT to the client following the standard bearer schema.
    return TokenResponse(access_token=access_token, expires_in=expires_in)


@api_router.post("/logout", response_model=MessageResponse, responses={401: {"model": MessageResponse}})
@global_rate_limit
async def logout(request: Request, user: dict[str, Any] = Depends(get_current_user)) -> MessageResponse:  # noqa: ARG001
    """Invalidate the caller's JWT by recording it in an in-memory blacklist."""
    credentials = request.headers.get("Authorization", "")
    token = credentials.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    token_blacklist = getattr(request.app.state, "token_blacklist", None)
    if token_blacklist is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Logout backend unavailable")

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    # Store the revoked token with an expiration matching the JWT lifetime for stateless logout.
    await token_blacklist.add(token, expires_at=expires_at)
    return MessageResponse(detail="Successfully logged out")


@api_router.get("/me", response_model=UserResponse, responses={401: {"model": MessageResponse}})
@global_rate_limit
async def read_current_user(request: Request, user: dict[str, Any] = Depends(get_current_user)) -> UserResponse:  # noqa: ARG001
    """Return the authenticated user's public profile."""
    return UserResponse(id=str(user["id"]), email=user["email"])
