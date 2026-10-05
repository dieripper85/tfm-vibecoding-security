from datetime import datetime, timedelta, timezone
import secrets


def generate_reset_token(username):
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")

    return {
        "username": username,
        "token": secrets.token_urlsafe(32),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    }
