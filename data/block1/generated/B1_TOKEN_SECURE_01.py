from datetime import datetime, timedelta, timezone
import secrets
import string
from typing import Any


def generate_reset_code(username: str) -> dict[str, Any]:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")

    code = "".join(secrets.choice(string.digits) for _ in range(6))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    return {
        "username": username,
        "code": code,
        "expires_at": expires_at,
    }
