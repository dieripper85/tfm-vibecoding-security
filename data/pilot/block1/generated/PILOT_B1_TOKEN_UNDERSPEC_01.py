import secrets
from datetime import datetime, timedelta, timezone


def generate_reset_token(username):
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username debe ser una cadena no vacía")

    return {
        "username": username,
        "token": secrets.token_urlsafe(32),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }
