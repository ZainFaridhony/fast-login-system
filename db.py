"""Supabase database helpers."""
from __future__ import annotations

import asyncio
import os
from functools import lru_cache
from typing import Any

from fastapi import HTTPException, status
from supabase import Client, create_client

SUPABASE_TABLE = os.getenv("SUPABASE_USERS_TABLE", "users")


@lru_cache(maxsize=1)
def get_supabase_client() -> Client:
    """Instantiate and cache the Supabase client."""
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        raise RuntimeError("Supabase configuration is missing")
    return create_client(url, key)


async def _run_blocking(callable_obj: Any, /, *args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(callable_obj, *args, **kwargs)


async def get_user_by_email(email: str) -> dict[str, Any] | None:
    """Fetch a user record by email from Supabase."""
    client = get_supabase_client()

    def _query() -> Any:
        # Retrieve at most one user matching the email address.
        return client.table(SUPABASE_TABLE).select("*").eq("email", email).limit(1).execute()

    response = await _run_blocking(_query)
    if getattr(response, "error", None):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Database query failed")
    users = response.data or []
    return users[0] if users else None


async def get_user_by_id(user_id: str) -> dict[str, Any] | None:
    """Fetch a user record by id from Supabase."""
    client = get_supabase_client()

    def _query() -> Any:
        return client.table(SUPABASE_TABLE).select("*").eq("id", user_id).limit(1).execute()

    response = await _run_blocking(_query)
    if getattr(response, "error", None):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Database query failed")
    users = response.data or []
    return users[0] if users else None


async def create_user(*, email: str, hashed_password: str) -> dict[str, Any]:
    """Create a new user in Supabase with a securely hashed password."""
    client = get_supabase_client()

    def _insert() -> Any:
        # Insert the user and ask Supabase to return the stored record for confirmation.
        return (
            client.table(SUPABASE_TABLE)
            .insert({"email": email, "password_hash": hashed_password})
            .select("*")
            .limit(1)
            .execute()
        )

    response = await _run_blocking(_insert)
    if getattr(response, "error", None):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to persist user")
    if not response.data:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")
    return response.data[0]
