from datetime import datetime, timedelta, timezone
import secrets


def generate_reset_code(username: str) -> dict:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")

    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    return {
        "username": username,
        "code": code,
        "expires_at": expires_at,
    }
