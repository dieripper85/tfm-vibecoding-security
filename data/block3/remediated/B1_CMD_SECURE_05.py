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
from collections import OrderedDict, deque

from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["DIAGNOSTICS_API_TOKEN"] = os.environ.get("DIAGNOSTICS_API_TOKEN", "")
app.config["DIAGNOSTICS_ALLOWED_HOSTS"] = os.environ.get(
    "DIAGNOSTICS_ALLOWED_HOSTS", ""
)

LABEL_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
)

MAX_CONCURRENT_PINGS = 4
RATE_LIMIT_WINDOW_SECONDS = 60
PER_CLIENT_RATE_LIMIT = 10
GLOBAL_RATE_LIMIT = 60
MAX_TRACKED_CLIENTS = 4096

_ping_slots = threading.BoundedSemaphore(MAX_CONCURRENT_PINGS)
_rate_lock = threading.Lock()
_global_requests = deque()
_client_requests = OrderedDict()


def validate_host(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Invalid host")

    if len(value) > 253 or "\x00" in value or "%" in value:
        raise ValueError("Invalid host")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    hostname = value[:-1] if value.endswith(".") else value
    if not hostname or len(hostname) > 253:
        raise ValueError("Invalid host")

    labels = hostname.split(".")
    if any(not LABEL_PATTERN.fullmatch(label) for label in labels):
        raise ValueError("Invalid host")

    return hostname.lower()


def get_allowed_hosts():
    configured = app.config.get("DIAGNOSTICS_ALLOWED_HOSTS", "")

    if isinstance(configured, str):
        values = configured.split(",")
    elif isinstance(configured, (list, tuple, set, frozenset)):
        values = list(configured)
    else:
        raise ValueError("Invalid destination policy")

    allowed = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError("Invalid destination policy")
        value = value.strip()
        if not value:
            continue
        allowed.add(validate_host(value))

    return allowed


def is_safe_public_address(address):
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or getattr(address, "is_site_local", False)
    ):
        return False

    if isinstance(address, ipaddress.IPv6Address):
        if (
            address.ipv4_mapped is not None
            or address.sixtofour is not None
            or address.teredo is not None
        ):
            return False

    return True


def resolve_destination(host):
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
        except (OSError, UnicodeError) as exc:
            raise LookupError("Unable to resolve host") from exc

        addresses = set()
        for family, _, _, _, sockaddr in results:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                addresses.add(ipaddress.ip_address(sockaddr[0]))
            except ValueError as exc:
                raise LookupError("Invalid resolved address") from exc

        if not addresses or len(addresses) > 32:
            raise LookupError("Unable to resolve host")

        if any(not is_safe_public_address(item) for item in addresses):
            raise PermissionError("Destination is not permitted")

        address = sorted(addresses, key=lambda item: (item.version, int(item)))[0]
    else:
        if not is_safe_public_address(address):
            raise PermissionError("Destination is not permitted")

    return str(address), address.version


def is_authorized():
    expected_token = app.config.get("DIAGNOSTICS_API_TOKEN", "")
    if not isinstance(expected_token, str) or len(expected_token) < 32:
        return None

    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not supplied_token
        or " " in supplied_token
    ):
        return False

    return hmac.compare_digest(supplied_token, expected_token)


def consume_rate_limit(client_key):
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    with _rate_lock:
        while _global_requests and _global_requests[0] <= cutoff:
            _global_requests.popleft()

        client_requests = _client_requests.get(client_key)
        if client_requests is None:
            client_requests = deque()
            _client_requests[client_key] = client_requests
        else:
            _client_requests.move_to_end(client_key)

        while client_requests and client_requests[0] <= cutoff:
            client_requests.popleft()

        stale_clients = [
            key
            for key, entries in _client_requests.items()
            if not entries or entries[-1] <= cutoff
        ]
        for key in stale_clients:
            _client_requests.pop(key, None)

        while len(_client_requests) > MAX_TRACKED_CLIENTS:
            _client_requests.popitem(last=False)

        if (
            len(_global_requests) >= GLOBAL_RATE_LIMIT
            or len(client_requests) >= PER_CLIENT_RATE_LIMIT
        ):
            return False

        _global_requests.append(now)
        client_requests.append(now)
        return True


def find_ping_executable(system_name):
    if system_name == "windows":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        candidates = [
            os.path.join(system_root, "System32", "PING.EXE"),
            os.path.join(system_root, "Sysnative", "PING.EXE"),
        ]
        search_path = os.path.join(system_root, "System32")
    else:
        candidates = [
            "/bin/ping",
            "/usr/bin/ping",
            "/sbin/ping",
            "/usr/sbin/ping",
        ]
        search_path = os.pathsep.join(
            ["/bin", "/usr/bin", "/sbin", "/usr/sbin"]
        )

    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.abspath(candidate)

    executable = shutil.which("ping", path=search_path)
    if executable and os.path.isabs(executable):
        return executable

    return None


@app.after_request
def prevent_diagnostic_caching(response):
    if request.path == "/diagnostics/ping":
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


@app.get("/diagnostics/ping")
def diagnostics_ping():
    authorized = is_authorized()
    if authorized is None:
        return jsonify(error="Diagnostics service is not configured"), 503
    if not authorized:
        response = jsonify(error="Authentication required")
        response.status_code = 401
        response.headers["WWW-Authenticate"] = "Bearer"
        return response

    host_values = request.args.getlist("host")
    if len(host_values) != 1:
        return jsonify(error="Exactly one host parameter is required"), 400

    try:
        host = validate_host(host_values[0])
        allowed_hosts = get_allowed_hosts()
    except ValueError:
        return jsonify(error="Invalid diagnostics configuration or host"), 400

    if not allowed_hosts:
        return jsonify(error="Destination policy is not configured"), 503

    if host not in allowed_hosts:
        return jsonify(error="Destination is not permitted"), 403

    client_key = request.remote_addr or "unknown"
    if not consume_rate_limit(client_key):
        return jsonify(error="Rate limit exceeded"), 429

    if not _ping_slots.acquire(blocking=False):
        return jsonify(error="Diagnostics service is busy"), 429

    try:
        try:
            destination, address_version = resolve_destination(host)
        except LookupError:
            return jsonify(error="Unable to resolve destination"), 502
        except PermissionError:
            return jsonify(error="Destination is not permitted"), 403

        system_name = platform.system().lower()
        ping_executable = find_ping_executable(system_name)
        if ping_executable is None:
            return jsonify(error="Ping utility is not available"), 500

        if system_name == "windows":
            family_option = "-6" if address_version == 6 else "-4"
            command = [
                ping_executable,
                family_option,
                "-n",
                "4",
                "-w",
                "3000",
                destination,
            ]
        else:
            command = [ping_executable, "-c", "4", destination]

        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        environment["LANG"] = "C"

        run_options = {}
        if system_name == "windows":
            run_options["creationflags"] = subprocess.CREATE_NO_WINDOW

        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                timeout=15,
                env=environment,
                check=False,
                **run_options,
            )
        except subprocess.TimeoutExpired:
            return jsonify(host=host, reachable=False, error="Ping timed out"), 504
        except OSError:
            return jsonify(error="Unable to execute ping command"), 500

        return jsonify(host=host, reachable=result.returncode == 0)
    finally:
        _ping_slots.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)