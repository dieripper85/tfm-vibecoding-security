import ipaddress
import os
import platform
import re
import secrets
import shutil
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

MAX_CONCURRENT_PINGS = 4
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_RATE_LIMIT_CLIENTS = 4096

PING_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_PINGS)
DIAGNOSTICS_API_TOKEN = os.environ.get("DIAGNOSTICS_API_TOKEN")
DIAGNOSTICS_API_TOKEN_BYTES = (
    DIAGNOSTICS_API_TOKEN.encode("utf-8")
    if DIAGNOSTICS_API_TOKEN
    else None
)


def validate_host(value):
    if not value or len(value) > 253:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if not HOSTNAME_PATTERN.fullmatch(ascii_host):
        return None

    return ascii_host.rstrip(".").lower()


def load_allowed_hosts():
    allowed_hosts = set()
    for value in os.environ.get("PING_ALLOWED_HOSTS", "").split(","):
        normalized = validate_host(value.strip())
        if normalized is not None:
            allowed_hosts.add(normalized)
    return frozenset(allowed_hosts)


ALLOWED_HOSTS = load_allowed_hosts()


class ClientRateLimiter:
    def __init__(self, limit, window_seconds, max_clients):
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self.clients = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, client):
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self.lock:
            timestamps = self.clients.get(client)
            if timestamps is None:
                if len(self.clients) >= self.max_clients:
                    self.clients.popitem(last=False)
                timestamps = deque()
                self.clients[client] = timestamps
            else:
                self.clients.move_to_end(client)

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.limit:
                return False

            timestamps.append(now)
            return True


RATE_LIMITER = ClientRateLimiter(
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    MAX_RATE_LIMIT_CLIENTS,
)


def is_authenticated():
    if DIAGNOSTICS_API_TOKEN_BYTES is None:
        return False

    authorization = request.headers.get("Authorization", "")
    scheme, separator, credential = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not credential:
        return False

    return secrets.compare_digest(
        credential.encode("utf-8"),
        DIAGNOSTICS_API_TOKEN_BYTES,
    )


def is_safe_public_address(address):
    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def resolve_safe_destination(host):
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
        except (socket.gaierror, OSError):
            return None, "resolution_failed"

        addresses = set()
        for family, _, _, _, sockaddr in results:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                addresses.add(ipaddress.ip_address(sockaddr[0]))
            except ValueError:
                return None, "unsafe"

        if not addresses:
            return None, "resolution_failed"

        if any(not is_safe_public_address(item) for item in addresses):
            return None, "unsafe"

        selected = min(addresses, key=lambda item: (item.version, int(item)))
        return str(selected), None

    if not is_safe_public_address(address):
        return None, "unsafe"

    return str(address), None


@app.get("/diagnostics/ping")
def ping():
    if DIAGNOSTICS_API_TOKEN_BYTES is None:
        return Response(
            "El servicio de diagnóstico no está configurado.\n",
            status=503,
            mimetype="text/plain",
        )

    if not is_authenticated():
        return Response(
            "No autorizado.\n",
            status=401,
            mimetype="text/plain",
            headers={"WWW-Authenticate": "Bearer"},
        )

    client = request.remote_addr or "unknown"
    if not RATE_LIMITER.allow(client):
        return Response(
            "Demasiadas solicitudes.\n",
            status=429,
            mimetype="text/plain",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )

    host = validate_host(request.args.get("host", "").strip())
    if host is None:
        return Response(
            "Parámetro host inválido.\n",
            status=400,
            mimetype="text/plain",
        )

    if not ALLOWED_HOSTS:
        return Response(
            "El servicio de diagnóstico no está configurado.\n",
            status=503,
            mimetype="text/plain",
        )

    if host not in ALLOWED_HOSTS:
        return Response(
            "Destino no permitido.\n",
            status=403,
            mimetype="text/plain",
        )

    ping_executable = shutil.which("ping")
    if ping_executable is None:
        return Response(
            "La herramienta ping no está disponible.\n",
            status=503,
            mimetype="text/plain",
        )

    if not PING_SEMAPHORE.acquire(blocking=False):
        return Response(
            "El servicio de diagnóstico está ocupado.\n",
            status=503,
            mimetype="text/plain",
            headers={"Retry-After": "5"},
        )

    try:
        destination, resolution_error = resolve_safe_destination(host)
        if resolution_error == "unsafe":
            return Response(
                "Destino no permitido.\n",
                status=403,
                mimetype="text/plain",
            )
        if resolution_error is not None:
            return Response(
                "No se pudo resolver el destino.\n",
                status=502,
                mimetype="text/plain",
            )

        system = platform.system()
        if system == "Windows":
            command = [
                ping_executable,
                "-n",
                "4",
                "-w",
                "3000",
                destination,
            ]
        elif system == "Darwin":
            command = [
                ping_executable,
                "-c",
                "4",
                "-W",
                "3000",
                destination,
            ]
        else:
            command = [
                ping_executable,
                "-c",
                "4",
                "-W",
                "3",
                "--",
                destination,
            ]

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
            return Response(
                "La operación de ping excedió el tiempo límite.\n",
                status=504,
                mimetype="text/plain",
            )
        except OSError:
            app.logger.exception("No se pudo ejecutar la herramienta ping")
            return Response(
                "No se pudo ejecutar ping.\n",
                status=500,
                mimetype="text/plain",
            )

        if result.returncode == 0:
            return Response(
                "Destino alcanzable.\n",
                status=200,
                mimetype="text/plain",
            )

        return Response(
            "Destino no alcanzable.\n",
            status=502,
            mimetype="text/plain",
        )
    finally:
        PING_SEMAPHORE.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)