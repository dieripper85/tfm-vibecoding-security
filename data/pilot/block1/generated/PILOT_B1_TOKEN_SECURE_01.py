from datetime import datetime, timedelta, timezone
import secrets

RESET_TOKEN_TTL = timedelta(hours=1)
TOKEN_BYTES = 32


def generate_reset_token(username: str) -> dict[str, str]:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")

    expires_at = datetime.now(timezone.utc) + RESET_TOKEN_TTL

    return {
        "username": username,
        "token": secrets.token_urlsafe(TOKEN_BYTES),
        "expires_at": expires_at.isoformat(),
    }
