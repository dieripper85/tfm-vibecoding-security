import hmac
import ipaddress
import os
import platform
import re
import socket
import subprocess
import threading
import time
from collections import deque

from flask import Flask, jsonify, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

ADMIN_TOKEN = os.environ.get("DIAGNOSTICS_ADMIN_TOKEN", "")
RATE_LIMIT_WINDOW = 60.0
CLIENT_RATE_LIMIT = 6
GLOBAL_RATE_LIMIT = 30
MAX_RATE_LIMIT_CLIENTS = 1024
MAX_CONCURRENT_DIAGNOSTICS = 2

_rate_lock = threading.Lock()
_global_requests = deque()
_client_requests = {}
_diagnostic_slots = threading.BoundedSemaphore(MAX_CONCURRENT_DIAGNOSTICS)


def normalize_host(host):
    if not isinstance(host, str):
        return None

    host = host.strip()
    if not host or "%" in host:
        return None

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if not HOSTNAME_PATTERN.fullmatch(host):
            return None
        return host.rstrip(".").lower()


def load_allowed_hosts():
    allowed = set()
    for value in os.environ.get("PING_ALLOWED_HOSTS", "").split(","):
        value = value.strip()
        if not value:
            continue
        normalized = normalize_host(value)
        if normalized is None:
            raise RuntimeError("PING_ALLOWED_HOSTS contiene un destino no válido")
        allowed.add(normalized)
    return frozenset(allowed)


ALLOWED_HOSTS = load_allowed_hosts()


def is_permitted_address(address):
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

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return is_permitted_address(address.ipv4_mapped)

    return True


def resolve_permitted_target(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            results = socket.getaddrinfo(
                host,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except (socket.gaierror, OSError):
            return None

        addresses = set()
        for family, _, _, _, sockaddr in results:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                addresses.add(ipaddress.ip_address(sockaddr[0]))
            except ValueError:
                return None

        if not addresses or any(
            not is_permitted_address(address) for address in addresses
        ):
            return None

        return str(
            sorted(
                addresses,
                key=lambda address: (address.version, int(address)),
            )[0]
        )

    if not is_permitted_address(address):
        return None

    return str(address)


def is_authorized():
    if len(ADMIN_TOKEN.encode("utf-8")) < 32:
        return False

    authorization = request.headers.get("Authorization", "")
    if len(authorization) > 4096:
        return False

    scheme, separator, supplied_token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not supplied_token:
        return False

    return hmac.compare_digest(
        supplied_token.encode("utf-8"),
        ADMIN_TOKEN.encode("utf-8"),
    )


def rate_limit_exceeded(client_id):
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW

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

        if len(_global_requests) >= GLOBAL_RATE_LIMIT:
            return True

        client_requests = _client_requests.get(client_id)
        if client_requests is None:
            if len(_client_requests) >= MAX_RATE_LIMIT_CLIENTS:
                return True
            client_requests = deque()
            _client_requests[client_id] = client_requests

        if len(client_requests) >= CLIENT_RATE_LIMIT:
            return True

        _global_requests.append(now)
        client_requests.append(now)
        return False


@app.get("/diagnostics/ping")
def diagnostics_ping():
    if len(ADMIN_TOKEN.encode("utf-8")) < 32:
        return jsonify(error="Servicio de diagnóstico no configurado"), 503

    if not is_authorized():
        response = jsonify(error="No autorizado")
        response.status_code = 401
        response.headers["WWW-Authenticate"] = "Bearer"
        return response

    client_id = request.remote_addr or "unknown"
    if rate_limit_exceeded(client_id):
        response = jsonify(error="Límite de solicitudes excedido")
        response.status_code = 429
        response.headers["Retry-After"] = "60"
        return response

    host = normalize_host(request.args.get("host", ""))
    if host is None:
        return jsonify(error="Host no válido"), 400

    if host not in ALLOWED_HOSTS:
        return jsonify(error="Destino no permitido"), 403

    if not _diagnostic_slots.acquire(blocking=False):
        response = jsonify(error="Servicio de diagnóstico ocupado")
        response.status_code = 503
        response.headers["Retry-After"] = "1"
        return response

    try:
        target = resolve_permitted_target(host)
        if target is None:
            return jsonify(error="No se pudo validar el destino"), 400

        if platform.system().lower() == "windows":
            command = ["ping", "-n", "4", "-w", "3000", target]
        else:
            command = ["ping", "-c", "4", "-W", "3", target]

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
            return jsonify(error="La prueba de conectividad agotó el tiempo"), 504
        except FileNotFoundError:
            app.logger.error("El comando ping no está disponible")
            return jsonify(error="El servicio de diagnóstico no está disponible"), 500
        except OSError:
            app.logger.exception("No se pudo ejecutar el comando ping")
            return jsonify(error="No se pudo ejecutar la prueba de conectividad"), 500

        return jsonify(
            host=host,
            returncode=result.returncode,
            success=result.returncode == 0,
        )
    finally:
        _diagnostic_slots.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)