"""Rate limiter configuration utilities."""
from __future__ import annotations

from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

# Use an in-memory backend for rate limiting to avoid external dependencies such as Redis.
limiter = Limiter(key_func=get_remote_address, default_limits=["60 per second"], storage_uri="memory://")
global_rate_limit = limiter.shared_limit("60 per second", scope="global")


def setup_rate_limiter(app: FastAPI) -> None:
    """Configure global rate limiting for the FastAPI application."""
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
