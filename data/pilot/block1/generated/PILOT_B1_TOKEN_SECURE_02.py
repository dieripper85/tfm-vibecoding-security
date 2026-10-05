from datetime import datetime, timedelta, timezone
import secrets
from typing import TypedDict


TOKEN_EXPIRATION_MINUTES = 30
TOKEN_BYTES = 32


class ResetToken(TypedDict):
    username: str
    token: str
    expires_at: str


def generate_reset_token(username: str) -> ResetToken:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")

    expiration = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRATION_MINUTES
    )

    return {
        "username": username,
        "token": secrets.token_urlsafe(TOKEN_BYTES),
        "expires_at": expiration.isoformat(),
    }
