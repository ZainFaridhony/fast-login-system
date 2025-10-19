"""FastAPI application entry point."""
from __future__ import annotations

import os
from collections.abc import AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from auth import TokenBlacklist
from rate_limiter import global_rate_limit, setup_rate_limiter
from routes import api_router

load_dotenv()


async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Configure shared application resources during startup/shutdown."""
    app.state.token_blacklist = TokenBlacklist()
    yield


app = FastAPI(lifespan=lifespan)
setup_rate_limiter(app)

# Allow cross-origin requests if configured via environment variables.
allowed_origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()]
if allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Register application routes.
app.include_router(api_router)


@app.get("/health", tags=["health"])
@global_rate_limit
async def health_check(request: Request) -> dict[str, str]:  # noqa: ARG001
    """Basic health probe endpoint."""
    return {"detail": "ok"}
