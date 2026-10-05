import ipaddress
import os
import platform
import re
import secrets
import socket
import subprocess
import threading
import time
from collections import deque

from flask import Flask, Response, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)

DIAGNOSTICS_TOKEN = os.environ.get("DIAGNOSTICS_API_TOKEN", "")
MAX_CONCURRENT_PINGS = 4
RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW_SECONDS = 60

ping_slots = threading.BoundedSemaphore(MAX_CONCURRENT_PINGS)
rate_limit_lock = threading.Lock()
request_times = deque()


def text_response(message, status, headers=None):
    return Response(
        message,
        status=status,
        headers=headers,
        content_type="text/plain; charset=utf-8",
    )


def normalize_host(value):
    if not isinstance(value, str) or len(value) > 255:
        raise ValueError("Parámetro host inválido")

    host = value.strip()

    if not host or len(host) > 253 or "%" in host:
        raise ValueError("Parámetro host inválido")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("Parámetro host inválido") from exc

    if not host or len(host) > 253 or not HOSTNAME_PATTERN.fullmatch(host):
        raise ValueError("Parámetro host inválido")

    return host


def load_allowed_hosts():
    allowed = set()

    for value in os.environ.get("DIAGNOSTICS_ALLOWED_HOSTS", "").split(","):
        value = value.strip()
        if not value:
            continue
        try:
            allowed.add(normalize_host(value))
        except ValueError:
            app.logger.warning("Se ignoró un host inválido en DIAGNOSTICS_ALLOWED_HOSTS")

    return frozenset(allowed)


ALLOWED_HOSTS = load_allowed_hosts()


def is_authenticated():
    if not DIAGNOSTICS_TOKEN:
        return False

    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")

    if not separator or scheme.lower() != "bearer" or not supplied_token:
        return False

    return secrets.compare_digest(
        supplied_token.encode("utf-8"),
        DIAGNOSTICS_TOKEN.encode("utf-8"),
    )


def rate_limit_exceeded():
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    with rate_limit_lock:
        while request_times and request_times[0] <= cutoff:
            request_times.popleft()

        if len(request_times) >= RATE_LIMIT_REQUESTS:
            return True

        request_times.append(now)
        return False


def resolve_global_address(host):
    try:
        literal_address = ipaddress.ip_address(host)
    except ValueError:
        literal_address = None

    if literal_address is not None:
        if not literal_address.is_global:
            raise ValueError("Destino no permitido")
        return str(literal_address)

    try:
        results = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise LookupError("No se pudo resolver el destino") from exc

    addresses = []
    seen = set()

    for family, _, _, _, sockaddr in results:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue

        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise ValueError("Destino no permitido") from exc

        if not address.is_global:
            raise ValueError("Destino no permitido")

        normalized = str(address)
        if normalized not in seen:
            seen.add(normalized)
            addresses.append(normalized)

    if not addresses:
        raise LookupError("No se pudo resolver el destino")

    return addresses[0]


@app.get("/diagnostics/ping")
def ping():
    if not DIAGNOSTICS_TOKEN:
        return text_response("Servicio de diagnóstico no disponible\n", 503)

    if not is_authenticated():
        return text_response(
            "No autorizado\n",
            401,
            {"WWW-Authenticate": 'Bearer realm="diagnostics"'},
        )

    if rate_limit_exceeded():
        return text_response(
            "Demasiadas solicitudes\n",
            429,
            {"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )

    host_value = request.args.get("host")

    if host_value is None:
        return text_response("Falta el parámetro host\n", 400)

    try:
        host = normalize_host(host_value)
    except ValueError:
        return text_response("Parámetro host inválido\n", 400)

    if host not in ALLOWED_HOSTS:
        return text_response("Destino no autorizado\n", 403)

    if not ping_slots.acquire(blocking=False):
        return text_response(
            "Servicio de diagnóstico ocupado\n",
            503,
            {"Retry-After": "1"},
        )

    try:
        try:
            address = resolve_global_address(host)
        except LookupError:
            return text_response("No se pudo resolver el destino\n", 502)
        except ValueError:
            return text_response("Destino no autorizado\n", 403)

        if platform.system() == "Windows":
            command = ["ping", "-n", "1", "-w", "3000", address]
        else:
            command = ["ping", "-c", "1", address]

        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return text_response("Tiempo de espera agotado\n", 504)
        except FileNotFoundError:
            app.logger.error("El comando ping no está disponible")
            return text_response("Servicio de diagnóstico no disponible\n", 500)
        except OSError:
            app.logger.exception("No se pudo ejecutar el comando ping")
            return text_response("No se pudo ejecutar el diagnóstico\n", 500)

        if result.returncode == 0:
            return text_response("Ping correcto\n", 200)

        return text_response("Ping fallido\n", 502)
    finally:
        ping_slots.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)