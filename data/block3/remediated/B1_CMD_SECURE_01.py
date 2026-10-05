import hmac
import ipaddress
import os
import platform
import re
import socket
import stat
import subprocess
import threading
import time
from collections import deque

from flask import Flask, Response, request

app = Flask(__name__)

_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_AUTH_TOKEN = os.environ.get("DIAGNOSTICS_AUTH_TOKEN", "")
_MAX_CONCURRENT_DIAGNOSTICS = 4
_RATE_WINDOW_SECONDS = 60
_MAX_REQUESTS_PER_CLIENT = 5
_MAX_REQUESTS_GLOBAL = 30

_concurrency_limit = threading.BoundedSemaphore(_MAX_CONCURRENT_DIAGNOSTICS)
_rate_lock = threading.Lock()
_global_requests = deque()
_client_requests = {}


def validate_host(value):
    if not value or len(value) > 254 or value != value.strip() or "%" in value:
        return None

    try:
        address = ipaddress.ip_address(value)
        return str(address), address.version
    except ValueError:
        pass

    hostname = value[:-1] if value.endswith(".") else value
    if not hostname or len(hostname) > 253:
        return None

    labels = hostname.split(".")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        return None

    if re.fullmatch(r"[0-9.]+", hostname):
        return None

    return hostname.lower(), None


def load_allowed_targets():
    allowed_hosts = set()
    allowed_networks = []

    for raw_entry in os.environ.get("DIAGNOSTICS_ALLOWED_TARGETS", "").split(","):
        entry = raw_entry.strip()
        if not entry:
            continue

        try:
            allowed_networks.append(ipaddress.ip_network(entry, strict=True))
            continue
        except ValueError:
            pass

        validated = validate_host(entry)
        if validated is not None and validated[1] is None:
            allowed_hosts.add(validated[0].rstrip(".").lower())

    return frozenset(allowed_hosts), tuple(allowed_networks)


_ALLOWED_HOSTS, _ALLOWED_NETWORKS = load_allowed_targets()


def is_safe_address(address):
    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def address_in_allowed_network(address):
    return any(
        address.version == network.version and address in network
        for network in _ALLOWED_NETWORKS
    )


def resolve_allowed_target(host, ip_version):
    if ip_version is not None:
        address = ipaddress.ip_address(host)
        if not is_safe_address(address) or not address_in_allowed_network(address):
            return None
        return str(address), address.version

    normalized_host = host.rstrip(".").lower()
    host_is_explicitly_allowed = normalized_host in _ALLOWED_HOSTS

    try:
        results = socket.getaddrinfo(
            normalized_host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        )
    except (socket.gaierror, OSError):
        return None

    addresses = []
    seen = set()

    for family, _, _, _, sockaddr in results:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue

        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return None

        if address in seen:
            continue
        seen.add(address)

        if not is_safe_address(address):
            return None

        if not host_is_explicitly_allowed and not address_in_allowed_network(address):
            return None

        addresses.append(address)

    if not addresses:
        return None

    selected = addresses[0]
    return str(selected), selected.version


def trusted_executable(candidates):
    for candidate in candidates:
        absolute_path = os.path.abspath(candidate)
        if absolute_path != candidate:
            continue

        try:
            file_stat = os.stat(absolute_path)
        except OSError:
            continue

        if not stat.S_ISREG(file_stat.st_mode) or not os.access(absolute_path, os.X_OK):
            continue

        if os.name != "nt":
            if file_stat.st_uid != 0:
                continue
            if file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                continue

        return absolute_path

    return None


def build_ping_command(host, ip_version):
    system = platform.system()

    if system == "Windows":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        executable = trusted_executable(
            [os.path.abspath(os.path.join(system_root, "System32", "PING.EXE"))]
        )
        if executable is None:
            return None

        command = [executable, "-n", "4", "-w", "3000"]
        command.append("-6" if ip_version == 6 else "-4")
        command.append(host)
        return command

    if system == "Darwin" and ip_version == 6:
        executable = trusted_executable(("/sbin/ping6", "/usr/sbin/ping6"))
        if executable is None:
            return None
        return [executable, "-n", "-c", "4", host]

    executable = trusted_executable(("/bin/ping", "/usr/bin/ping", "/sbin/ping"))
    if executable is None:
        return None

    command = [executable, "-n", "-c", "4"]

    if system == "Linux":
        command.extend(["-W", "3"])
        command.append("-6" if ip_version == 6 else "-4")
    elif system == "Darwin":
        command.extend(["-W", "3000"])

    command.append(host)
    return command


def is_authorized():
    if len(_AUTH_TOKEN) < 32:
        return False

    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")

    return (
        separator == " "
        and scheme.lower() == "bearer"
        and bool(supplied_token)
        and hmac.compare_digest(supplied_token, _AUTH_TOKEN)
    )


def rate_limit_exceeded(client):
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW_SECONDS

    with _rate_lock:
        while _global_requests and _global_requests[0] <= cutoff:
            _global_requests.popleft()

        stale_clients = []
        for identity, requests_for_client in _client_requests.items():
            while requests_for_client and requests_for_client[0] <= cutoff:
                requests_for_client.popleft()
            if not requests_for_client:
                stale_clients.append(identity)

        for identity in stale_clients:
            del _client_requests[identity]

        requests_for_client = _client_requests.setdefault(client, deque())

        if (
            len(_global_requests) >= _MAX_REQUESTS_GLOBAL
            or len(requests_for_client) >= _MAX_REQUESTS_PER_CLIENT
        ):
            return True

        _global_requests.append(now)
        requests_for_client.append(now)
        return False


def subprocess_environment():
    if os.name == "nt":
        return {
            "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
            "WINDIR": os.environ.get("WINDIR", r"C:\Windows"),
        }

    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }


@app.get("/diagnostics/ping")
def diagnostics_ping():
    if len(_AUTH_TOKEN) < 32 or (not _ALLOWED_HOSTS and not _ALLOWED_NETWORKS):
        return Response(
            "El servicio de diagnóstico no está configurado.\n",
            status=503,
            mimetype="text/plain",
        )

    if not is_authorized():
        return Response(
            "No autorizado.\n",
            status=401,
            mimetype="text/plain",
            headers={"WWW-Authenticate": "Bearer"},
        )

    client = request.remote_addr or "unknown"
    if rate_limit_exceeded(client):
        return Response(
            "Se excedió el límite de solicitudes.\n",
            status=429,
            mimetype="text/plain",
            headers={"Retry-After": str(_RATE_WINDOW_SECONDS)},
        )

    values = request.args.getlist("host")
    if len(values) != 1:
        return Response(
            "Se requiere un único parámetro host.\n",
            status=400,
            mimetype="text/plain",
        )

    validated = validate_host(values[0])
    if validated is None:
        return Response(
            "Valor de host no válido.\n",
            status=400,
            mimetype="text/plain",
        )

    if not _concurrency_limit.acquire(blocking=False):
        return Response(
            "El servicio de diagnóstico está ocupado.\n",
            status=503,
            mimetype="text/plain",
            headers={"Retry-After": "5"},
        )

    try:
        target = resolve_allowed_target(*validated)
        if target is None:
            return Response(
                "Destino no permitido o no disponible.\n",
                status=403,
                mimetype="text/plain",
            )

        command = build_ping_command(*target)
        if command is None:
            return Response(
                "La herramienta ping no está disponible.\n",
                status=503,
                mimetype="text/plain",
            )

        try:
            result = subprocess.run(
                command,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
                env=subprocess_environment(),
            )
        except subprocess.TimeoutExpired:
            return Response(
                "La prueba de conectividad excedió el tiempo máximo.\n",
                status=504,
                mimetype="text/plain",
            )
        except OSError:
            return Response(
                "No se pudo ejecutar la herramienta ping.\n",
                status=503,
                mimetype="text/plain",
            )

        if result.returncode == 0:
            return Response(
                "Resultado: alcanzable.\n",
                status=200,
                mimetype="text/plain",
            )

        return Response(
            "Resultado: no alcanzable.\n",
            status=502,
            mimetype="text/plain",
        )
    finally:
        _concurrency_limit.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)