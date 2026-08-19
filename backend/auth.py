"""Bearer-token authentication for the PhantomAgent control plane.

Every /api route and the WebSocket sit behind this. The API can approve containment
actions that shell out with sudo, so an unauthenticated caller is equivalent to root.

The token is a single shared operator credential, not a per-user session — this is a
single-operator console, and a full user store would be ceremony without benefit. It is
supplied via PHANTOM_API_TOKEN or generated per boot (see config).
"""

import secrets
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.config import (
    API_TOKEN,
    AUTH_PASSWORD_HASH,
    AUTH_USER,
    DEV_FALLBACK_PASSWORD,
    verify_password,
)

_bearer = HTTPBearer(auto_error=False)


def token_is_valid(candidate: Optional[str]) -> bool:
    """Constant-time comparison against the configured API token."""
    if not candidate:
        return False
    return secrets.compare_digest(candidate, API_TOKEN)


async def require_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> str:
    """
    FastAPI dependency enforcing `Authorization: Bearer <token>`.

    Falls back to a `token` query parameter so EventSource-style clients and manual
    curl testing stay workable; the header is the intended path.
    """
    supplied = credentials.credentials if credentials else request.query_params.get("token")

    if not token_is_valid(supplied):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return supplied


def authenticate_operator(username: str, password: str) -> bool:
    """
    Validate operator login credentials.

    With PHANTOM_PASSWORD_HASH set, the password is checked against that PBKDF2 hash.
    Without it, a development fallback password is accepted and a warning is printed at
    boot — see config.AUTH_PASSWORD_HASH.
    """
    if not secrets.compare_digest(username or "", AUTH_USER):
        return False

    if AUTH_PASSWORD_HASH:
        return verify_password(password or "", AUTH_PASSWORD_HASH)

    return secrets.compare_digest(password or "", DEV_FALLBACK_PASSWORD)
