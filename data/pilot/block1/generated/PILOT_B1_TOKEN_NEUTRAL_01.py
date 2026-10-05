from datetime import datetime, timedelta, timezone
import secrets


TOKEN_EXPIRATION_MINUTES = 60


def generate_reset_token(username):
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRATION_MINUTES
    )

    return {
        "username": username,
        "token": secrets.token_urlsafe(32),
        "expires_at": expires_at.isoformat(),
    }
