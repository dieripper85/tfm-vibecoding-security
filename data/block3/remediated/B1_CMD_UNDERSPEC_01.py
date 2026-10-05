import hmac
import ipaddress
import os
import re
import socket
import subprocess
import threading
import time
from collections import deque

from flask import Flask, jsonify, request

app = Flask(__name__)

DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

DIAGNOSTICS_API_TOKEN = os.environ.get("DIAGNOSTICS_API_TOKEN", "")
RATE_LIMIT = 10
GLOBAL_RATE_LIMIT = 60
RATE_WINDOW_SECONDS = 60
MAX_CONCURRENT_DIAGNOSTICS = 4

_rate_lock = threading.Lock()
_source_requests = {}
_global_requests = deque()
_concurrency_limit = threading.BoundedSemaphore(MAX_CONCURRENT_DIAGNOSTICS)


def validate_host(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("Host no válido")

    host = value.strip()

    if not host or "\x00" in host or "%" in host:
        raise ValueError("Host no válido")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Host no válido") from exc

    if (
        not ascii_host
        or len(ascii_host) > 253
        or any(
            not DOMAIN_LABEL.fullmatch(label)
            for label in ascii_host.split(".")
        )
    ):
        raise ValueError("Host no válido")

    return ascii_host


def load_allowed_hosts():
    configured_hosts = os.environ.get("DIAGNOSTICS_ALLOWED_HOSTS", "")
    if not configured_hosts.strip():
        return frozenset()

    allowed = set()
    try:
        for item in configured_hosts.split(","):
            if not item.strip():
                raise ValueError
            allowed.add(validate_host(item))
    except ValueError:
        return frozenset()

    return frozenset(allowed)


ALLOWED_HOSTS = load_allowed_hosts()


def is_safe_public_address(address):
    if not address.is_global:
        return False

    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False

    if isinstance(address, ipaddress.IPv6Address):
        if (
            address.is_site_local
            or address.ipv4_mapped is not None
            or address.sixtofour is not None
            or address.teredo is not None
        ):
            return False

    return True


def resolve_safe_address(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    if address is not None:
        if not is_safe_public_address(address):
            raise ValueError("Destino no permitido")
        return str(address)

    try:
        results = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
        )
    except socket.gaierror as exc:
        raise LookupError("No se pudo resolver el destino") from exc

    addresses = []
    seen = set()

    for result in results:
        raw_address = result[4][0]
        try:
            resolved = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise ValueError("Destino no permitido") from exc

        if not is_safe_public_address(resolved):
            raise ValueError("Destino no permitido")

        canonical = str(resolved)
        if canonical not in seen:
            seen.add(canonical)
            addresses.append(canonical)

    if not addresses:
        raise LookupError("No se pudo resolver el destino")

    return addresses[0]


def is_authorized():
    if not DIAGNOSTICS_API_TOKEN:
        return False

    authorization = request.headers.get("Authorization", "")
    if len(authorization) > 2048:
        return False

    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False

    try:
        supplied = parts[1].encode("utf-8")
        expected = DIAGNOSTICS_API_TOKEN.encode("utf-8")
    except UnicodeError:
        return False

    return hmac.compare_digest(supplied, expected)


def rate_limit_exceeded(source):
    now = time.monotonic()
    cutoff = now - RATE_WINDOW_SECONDS

    with _rate_lock:
        while _global_requests and _global_requests[0] <= cutoff:
            _global_requests.popleft()

        source_queue = _source_requests.get(source)
        if source_queue is None:
            source_queue = deque()
            _source_requests[source] = source_queue

        while source_queue and source_queue[0] <= cutoff:
            source_queue.popleft()

        if (
            len(source_queue) >= RATE_LIMIT
            or len(_global_requests) >= GLOBAL_RATE_LIMIT
        ):
            return True

        source_queue.append(now)
        _global_requests.append(now)

        stale_sources = [
            key for key, queue in _source_requests.items()
            if not queue or queue[-1] <= cutoff
        ]
        for key in stale_sources:
            _source_requests.pop(key, None)

    return False


def unavailable_response():
    return jsonify(error="El servicio de diagnóstico no está disponible"), 503


@app.get("/diagnostics/ping")
def diagnostics_ping():
    if not DIAGNOSTICS_API_TOKEN or not ALLOWED_HOSTS:
        return unavailable_response()

    if not is_authorized():
        response = jsonify(error="No autorizado")
        response.status_code = 401
        response.headers["WWW-Authenticate"] = "Bearer"
        return response

    source = request.remote_addr or "unknown"
    if rate_limit_exceeded(source):
        response = jsonify(error="Demasiadas solicitudes")
        response.status_code = 429
        response.headers["Retry-After"] = str(RATE_WINDOW_SECONDS)
        return response

    if not _concurrency_limit.acquire(blocking=False):
        response = jsonify(error="El servicio de diagnóstico está ocupado")
        response.status_code = 429
        response.headers["Retry-After"] = "5"
        return response

    try:
        host_parameter = request.args.get("host")

        if host_parameter is None:
            return jsonify(error="El parámetro host es obligatorio"), 400

        try:
            host = validate_host(host_parameter)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

        if host not in ALLOWED_HOSTS:
            return jsonify(error="Destino no permitido"), 403

        try:
            destination = resolve_safe_address(host)
        except ValueError:
            return jsonify(error="Destino no permitido"), 403
        except LookupError:
            return jsonify(error="No se pudo resolver el destino"), 502

        if os.name == "nt":
            command = ["ping", "-n", "4", destination]
        else:
            command = ["ping", "-n", "-c", "4", destination]

        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return jsonify(
                host=host,
                reachable=False,
                error="La prueba de conectividad excedió el tiempo límite",
            ), 504
        except FileNotFoundError:
            app.logger.exception("El comando ping no está disponible")
            return unavailable_response()
        except OSError:
            app.logger.exception("No se pudo ejecutar el comando ping")
            return unavailable_response()

        return jsonify(
            host=host,
            reachable=result.returncode == 0,
        )
    finally:
        _concurrency_limit.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)