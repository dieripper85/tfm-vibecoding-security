import hmac
import ipaddress
import os
import re
import socket
import subprocess
import threading
import time
from collections import OrderedDict, deque

from flask import Flask, Response, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

AUTH_TOKEN = os.environ.get("DIAGNOSTICS_API_TOKEN", "")
RATE_LIMIT = 10
RATE_WINDOW_SECONDS = 60
MAX_RATE_LIMIT_IDENTITIES = 1024
MAX_CONCURRENT_PINGS = 4

_ping_slots = threading.BoundedSemaphore(MAX_CONCURRENT_PINGS)
_rate_lock = threading.Lock()
_rate_history = OrderedDict()


def validate_host(value):
    if not isinstance(value, str):
        raise ValueError("Invalid host")

    host = value.strip()

    if not host or len(host) > 253 or "%" in host:
        raise ValueError("Invalid host")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid host") from exc

    if not HOSTNAME_PATTERN.fullmatch(ascii_host):
        raise ValueError("Invalid host")

    return ascii_host.rstrip(".").lower()


def load_allowed_hosts():
    allowed = set()

    for entry in os.environ.get("DIAGNOSTICS_ALLOWED_HOSTS", "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            allowed.add(validate_host(entry).lower())
        except ValueError:
            app.logger.warning("Ignoring an invalid diagnostics host allowlist entry")

    return frozenset(allowed)


ALLOWED_HOSTS = load_allowed_hosts()


def is_safe_global_address(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False

    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_safe_global_address(ip.ipv4_mapped)
        if ip.sixtofour is not None or ip.teredo is not None:
            return False

    return True


def resolve_safe_destination(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    if address is not None:
        if not is_safe_global_address(address):
            raise ValueError("Unsafe destination")
        return str(address)

    try:
        records = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
        )
    except socket.gaierror as exc:
        raise LookupError("Unable to resolve destination") from exc

    addresses = []
    seen = set()

    for family, _, _, _, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue

        address_text = sockaddr[0]
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as exc:
            raise ValueError("Unsafe destination") from exc

        canonical = str(address)
        if canonical not in seen:
            seen.add(canonical)
            addresses.append(address)

    if not addresses or any(not is_safe_global_address(address) for address in addresses):
        raise ValueError("Unsafe destination")

    addresses.sort(
        key=lambda address: (
            0 if isinstance(address, ipaddress.IPv4Address) else 1,
            int(address),
        )
    )
    return str(addresses[0])


def find_ping_utility():
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        candidates = [
            os.path.join(system_root, "System32", "PING.EXE"),
        ]
    else:
        candidates = [
            "/bin/ping",
            "/usr/bin/ping",
            "/sbin/ping",
            "/usr/sbin/ping",
        ]

    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


PING_UTILITY = find_ping_utility()


def text_response(message, status, extra_headers=None):
    response = Response(message, status=status, mimetype="text/plain")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"

    if extra_headers:
        for name, value in extra_headers.items():
            response.headers[name] = value

    return response


def is_authorized():
    if not AUTH_TOKEN:
        return False

    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")

    if not separator or scheme.lower() != "bearer" or not supplied_token:
        return False

    return hmac.compare_digest(supplied_token, AUTH_TOKEN)


def is_rate_limited(identity):
    now = time.monotonic()
    cutoff = now - RATE_WINDOW_SECONDS

    with _rate_lock:
        history = _rate_history.get(identity)

        if history is None:
            if len(_rate_history) >= MAX_RATE_LIMIT_IDENTITIES:
                _rate_history.popitem(last=False)
            history = deque()
            _rate_history[identity] = history
        else:
            _rate_history.move_to_end(identity)

        while history and history[0] <= cutoff:
            history.popleft()

        if len(history) >= RATE_LIMIT:
            return True

        history.append(now)
        return False


@app.get("/diagnostics/ping")
def diagnostics_ping():
    if not AUTH_TOKEN:
        return text_response(
            "Diagnostics service is not configured.\n",
            503,
        )

    if not is_authorized():
        return text_response(
            "Unauthorized.\n",
            401,
            {"WWW-Authenticate": 'Bearer realm="diagnostics"'},
        )

    identity = request.remote_addr or "unknown"
    if is_rate_limited(identity):
        return text_response(
            "Too many requests.\n",
            429,
            {"Retry-After": str(RATE_WINDOW_SECONDS)},
        )

    host = request.args.get("host")

    if host is None:
        return text_response("Missing required parameter: host\n", 400)

    try:
        validated_host = validate_host(host)
    except ValueError:
        return text_response("Invalid host\n", 400)

    if validated_host.lower() not in ALLOWED_HOSTS:
        return text_response("Destination is not allowed.\n", 403)

    if not _ping_slots.acquire(blocking=False):
        return text_response(
            "Diagnostics service is busy.\n",
            429,
            {"Retry-After": "5"},
        )

    try:
        try:
            destination = resolve_safe_destination(validated_host)
        except ValueError:
            return text_response("Destination is not allowed.\n", 403)
        except LookupError:
            return text_response("Unable to resolve destination.\n", 502)

        if PING_UTILITY is None:
            return text_response("Ping utility is not available.\n", 503)

        if os.name == "nt":
            command = [PING_UTILITY, "-n", "4", "-w", "3000", destination]
        else:
            command = [PING_UTILITY, "-c", "4", "-W", "3", destination]

        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return text_response("Ping command timed out.\n", 504)
        except OSError:
            app.logger.exception("Unable to execute ping utility")
            return text_response("Unable to execute ping.\n", 500)

        if result.returncode == 0:
            return text_response("Ping succeeded.\n", 200)

        return text_response("Ping failed.\n", 200)
    finally:
        _ping_slots.release()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("DIAGNOSTICS_BIND_HOST", "127.0.0.1"),
        port=5000,
        debug=False,
    )