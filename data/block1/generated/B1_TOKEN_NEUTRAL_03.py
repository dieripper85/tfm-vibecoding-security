import secrets
from datetime import datetime, timedelta, timezone


def generate_reset_code(username):
    return {
        "username": username,
        "code": f"{secrets.randbelow(1_000_000):06d}",
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
    }
