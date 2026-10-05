import hmac
import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
from collections import deque

from flask import Flask, Response, request

app = Flask(__name__)

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_RATE_WINDOW_SECONDS = 60.0
_PER_CLIENT_RATE_LIMIT = 10
_GLOBAL_RATE_LIMIT = 30
_MAX_CONCURRENT_DIAGNOSTICS = 4

_rate_lock = threading.Lock()
_global_requests = deque()
_client_requests = {}
_diagnostic_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_DIAGNOSTICS)


def normalize_host(value):
    host = value.strip()
    if not host or len(host) > 253:
        raise ValueError("Invalid host")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid host") from exc

    if not host or len(host) > 253:
        raise ValueError("Invalid host")

    labels = host.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Invalid host")

    return host


def _load_allowed_hosts():
    allowed = set()
    for value in os.environ.get("DIAGNOSTICS_ALLOWED_HOSTS", "").split(","):
        if not value.strip():
            continue
        try:
            allowed.add(normalize_host(value))
        except ValueError:
            continue
    return frozenset(allowed)


app.config["DIAGNOSTICS_TOKEN"] = os.environ.get("DIAGNOSTICS_TOKEN", "")
app.config["DIAGNOSTICS_ALLOWED_HOSTS"] = _load_allowed_hosts()


def _text_response(message, status, headers=None):
    response = Response(message, status=status, mimetype="text/plain")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    if headers:
        response.headers.update(headers)
    return response


def _is_authorized():
    expected = app.config.get("DIAGNOSTICS_TOKEN", "")
    if not isinstance(expected, str) or not expected:
        return False

    authorization = request.headers.get("Authorization", "")
    if len(authorization) > 4096:
        return False

    scheme, separator, credential = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not credential:
        return False

    return hmac.compare_digest(
        credential.encode("utf-8"),
        expected.encode("utf-8"),
    )


def _consume_rate_limit(client):
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW_SECONDS

    with _rate_lock:
        while _global_requests and _global_requests[0] <= cutoff:
            _global_requests.popleft()

        stale_clients = []
        for key, timestamps in _client_requests.items():
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            if not timestamps:
                stale_clients.append(key)

        for key in stale_clients:
            del _client_requests[key]

        client_requests = _client_requests.get(client)
        client_count = len(client_requests) if client_requests is not None else 0

        if (
            len(_global_requests) >= _GLOBAL_RATE_LIMIT
            or client_count >= _PER_CLIENT_RATE_LIMIT
        ):
            return False

        if client_requests is None:
            client_requests = deque()
            _client_requests[client] = client_requests

        _global_requests.append(now)
        client_requests.append(now)
        return True


def _is_permitted_address(address):
    if getattr(address, "scope_id", None):
        return False

    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return False
        if address.site_local:
            return False

    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def _resolve_public_target(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            results = socket.getaddrinfo(
                host,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_DGRAM,
            )
        except socket.gaierror as exc:
            raise ValueError("Unable to resolve host") from exc

        addresses = []
        seen = set()
        for family, _, _, _, sockaddr in results:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue

            raw_address = sockaddr[0]
            if "%" in raw_address:
                raise ValueError("Invalid resolved address")

            try:
                resolved = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise ValueError("Invalid resolved address") from exc

            canonical = str(resolved)
            if canonical not in seen:
                seen.add(canonical)
                addresses.append(resolved)

        if not addresses or any(not _is_permitted_address(item) for item in addresses):
            raise ValueError("Host resolves to a prohibited address")

        return str(addresses[0])

    if not _is_permitted_address(address):
        raise ValueError("Prohibited address")

    return str(address)


@app.get("/diagnostics/ping")
def diagnostics_ping():
    if not app.config.get("DIAGNOSTICS_TOKEN"):
        return _text_response("Diagnostic service is unavailable\n", 503)

    if not _is_authorized():
        return _text_response(
            "Unauthorized\n",
            401,
            {"WWW-Authenticate": 'Bearer realm="diagnostics"'},
        )

    client = request.remote_addr or "unknown"
    if not _consume_rate_limit(client):
        return _text_response(
            "Too many requests\n",
            429,
            {"Retry-After": str(int(_RATE_WINDOW_SECONDS))},
        )

    raw_host = request.args.get("host")
    if raw_host is None:
        return _text_response("Missing required parameter: host\n", 400)

    try:
        host = normalize_host(raw_host)
    except ValueError:
        return _text_response("Invalid host\n", 400)

    allowed_hosts = app.config.get("DIAGNOSTICS_ALLOWED_HOSTS", frozenset())
    if host not in allowed_hosts:
        return _text_response("Host is not permitted\n", 403)

    if not _diagnostic_slots.acquire(blocking=False):
        return _text_response(
            "Diagnostic service is busy\n",
            503,
            {"Retry-After": "1"},
        )

    try:
        try:
            target = _resolve_public_target(host)
        except ValueError:
            return _text_response("Ping failed\n", 502)

        ping_executable = shutil.which("ping")
        if ping_executable is None:
            return _text_response("Diagnostic service is unavailable\n", 503)

        system = platform.system()
        if system == "Windows":
            command = [ping_executable, "-n", "1", "-w", "3000", target]
        elif system == "Darwin":
            command = [ping_executable, "-c", "1", "-W", "3000", target]
        else:
            command = [ping_executable, "-c", "1", "-W", "3", target]

        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=6,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return _text_response("Ping timed out\n", 504)
        except OSError:
            app.logger.exception("Unable to execute diagnostic ping")
            return _text_response("Diagnostic service is unavailable\n", 500)

        if result.returncode == 0:
            return _text_response("Ping successful\n", 200)
        return _text_response("Ping failed\n", 502)
    finally:
        _diagnostic_slots.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)