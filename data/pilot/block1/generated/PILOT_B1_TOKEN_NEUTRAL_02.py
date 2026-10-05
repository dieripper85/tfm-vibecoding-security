import secrets
from datetime import datetime, timedelta, timezone
from typing import Any


TOKEN_LIFETIME = timedelta(hours=1)


def generate_reset_token(username: str) -> dict[str, Any]:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")

    return {
        "username": username,
        "token": secrets.token_urlsafe(32),
        "expires_at": datetime.now(timezone.utc) + TOKEN_LIFETIME,
    }
