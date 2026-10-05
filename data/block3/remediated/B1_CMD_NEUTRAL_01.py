import ctypes
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

LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
RATE_LIMIT_WINDOW = 60.0
RATE_LIMIT_PER_CLIENT = 10
RATE_LIMIT_GLOBAL = 30
MAX_CONCURRENT_DIAGNOSTICS = 4
MAX_RESOLVED_ADDRESSES = 16

_DIAGNOSTICS_TOKEN = os.environ.get("DIAGNOSTICS_API_TOKEN", "")
_rate_lock = threading.Lock()
_client_requests = {}
_global_requests = deque()
_concurrency_limit = threading.BoundedSemaphore(MAX_CONCURRENT_DIAGNOSTICS)


def validate_host(value):
    host = value.strip()
    if not host or len(host) > 253 or "\x00" in host or "%" in host:
        raise ValueError

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError from exc

    normalized = ascii_host[:-1] if ascii_host.endswith(".") else ascii_host
    normalized = normalized.lower()

    if not normalized or len(normalized) > 253:
        raise ValueError

    labels = normalized.split(".")
    if any(not LABEL_PATTERN.fullmatch(label) for label in labels):
        raise ValueError

    return normalized


def load_allowed_hosts():
    hosts = set()
    raw_value = os.environ.get("PING_ALLOWED_HOSTS", "")
    for value in raw_value.split(","):
        value = value.strip()
        if not value:
            continue
        hosts.add(validate_host(value))
    return frozenset(hosts)


def load_allowed_networks():
    networks = []
    raw_value = os.environ.get("PING_ALLOWED_NETWORKS", "")
    for value in raw_value.split(","):
        value = value.strip()
        if not value:
            continue
        networks.append(ipaddress.ip_network(value, strict=True))
    return tuple(networks)


try:
    ALLOWED_HOSTS = load_allowed_hosts()
    ALLOWED_NETWORKS = load_allowed_networks()
    ALLOWLIST_CONFIGURATION_VALID = True
except ValueError:
    ALLOWED_HOSTS = frozenset()
    ALLOWED_NETWORKS = ()
    ALLOWLIST_CONFIGURATION_VALID = False


def text_response(message, status):
    response = Response(message, status=status, mimetype="text/plain")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def is_authenticated():
    if not _DIAGNOSTICS_TOKEN:
        return False

    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not supplied_token:
        return False

    return hmac.compare_digest(supplied_token, _DIAGNOSTICS_TOKEN)


def rate_limit_exceeded(client):
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW

    with _rate_lock:
        while _global_requests and _global_requests[0] <= cutoff:
            _global_requests.popleft()

        expired_clients = []
        for key, timestamps in _client_requests.items():
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            if not timestamps:
                expired_clients.append(key)

        for key in expired_clients:
            del _client_requests[key]

        client_requests = _client_requests.setdefault(client, deque())

        if (
            len(_global_requests) >= RATE_LIMIT_GLOBAL
            or len(client_requests) >= RATE_LIMIT_PER_CLIENT
        ):
            return True

        _global_requests.append(now)
        client_requests.append(now)
        return False


def is_safe_public_address(address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped

    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def address_is_allowlisted(address):
    return any(
        address.version == network.version and address in network
        for network in ALLOWED_NETWORKS
    )


def resolve_authorized_target(host):
    try:
        direct_address = ipaddress.ip_address(host)
    except ValueError:
        direct_address = None

    if direct_address is not None:
        addresses = [direct_address]
    else:
        try:
            results = socket.getaddrinfo(
                host,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_DGRAM,
            )
        except socket.gaierror as exc:
            raise ValueError from exc

        addresses = []
        seen = set()
        for family, _, _, _, sockaddr in results:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue

            try:
                address = ipaddress.ip_address(sockaddr[0])
            except ValueError:
                continue

            if address not in seen:
                seen.add(address)
                addresses.append(address)

            if len(addresses) > MAX_RESOLVED_ADDRESSES:
                raise ValueError

    if not addresses:
        raise ValueError

    if any(not is_safe_public_address(address) for address in addresses):
        raise PermissionError

    host_is_allowlisted = host in ALLOWED_HOSTS
    if not host_is_allowlisted and any(
        not address_is_allowlisted(address) for address in addresses
    ):
        raise PermissionError

    addresses.sort(key=lambda address: (address.version != 4, int(address)))
    return str(addresses[0])


def find_ping_executable():
    if platform.system().lower() == "windows":
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
        if not length or length >= len(buffer):
            return None
        candidates = [os.path.join(buffer.value, "PING.EXE")]
    else:
        candidates = ["/usr/bin/ping", "/bin/ping", "/usr/sbin/ping", "/sbin/ping"]

    for candidate in candidates:
        try:
            resolved = os.path.realpath(candidate)
            file_stat = os.stat(resolved)
        except OSError:
            continue

        if stat.S_ISREG(file_stat.st_mode) and os.access(resolved, os.X_OK):
            return resolved

    return None


PING_EXECUTABLE = find_ping_executable()


def ping_environment(executable):
    environment = {
        "PATH": os.path.dirname(executable),
        "LANG": "C",
        "LC_ALL": "C",
    }

    if platform.system().lower() == "windows":
        system_root = os.path.dirname(os.path.dirname(executable))
        environment["SystemRoot"] = system_root
        environment["WINDIR"] = system_root

    return environment


@app.get("/diagnostics/ping")
def diagnostics_ping():
    if not _DIAGNOSTICS_TOKEN:
        return text_response(
            "El servicio de diagnóstico no está configurado.\n", 503
        )

    if not is_authenticated():
        response = text_response("No autorizado.\n", 401)
        response.headers["WWW-Authenticate"] = "Bearer"
        return response

    client = request.remote_addr or "unknown"
    if rate_limit_exceeded(client):
        response = text_response(
            "Se excedió el límite de solicitudes de diagnóstico.\n", 429
        )
        response.headers["Retry-After"] = str(int(RATE_LIMIT_WINDOW))
        return response

    if (
        not ALLOWLIST_CONFIGURATION_VALID
        or not ALLOWED_HOSTS and not ALLOWED_NETWORKS
    ):
        return text_response(
            "El servicio de diagnóstico no está configurado.\n", 503
        )

    raw_host = request.args.get("host")
    if raw_host is None:
        return text_response("Falta el parámetro host.\n", 400)

    try:
        host = validate_host(raw_host)
    except ValueError:
        return text_response("El parámetro host no es válido.\n", 400)

    if not _concurrency_limit.acquire(blocking=False):
        response = text_response(
            "El servicio de diagnóstico está ocupado.\n", 429
        )
        response.headers["Retry-After"] = "5"
        return response

    try:
        try:
            target = resolve_authorized_target(host)
        except PermissionError:
            return text_response("El destino no está autorizado.\n", 403)
        except ValueError:
            return text_response("No se pudo resolver el destino.\n", 400)

        if PING_EXECUTABLE is None:
            return text_response(
                "La herramienta de diagnóstico no está disponible.\n", 503
            )

        if platform.system().lower() == "windows":
            command = [PING_EXECUTABLE, "-n", "2", "-w", "2000", target]
        else:
            command = [PING_EXECUTABLE, "-c", "2", target]

        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
                check=False,
                env=ping_environment(PING_EXECUTABLE),
                close_fds=True,
            )
        except subprocess.TimeoutExpired:
            return text_response(
                "La prueba de conectividad excedió el tiempo límite.\n", 504
            )
        except OSError:
            app.logger.exception("No se pudo ejecutar la herramienta de diagnóstico")
            return text_response(
                "No se pudo ejecutar la prueba de conectividad.\n", 500
            )

        if result.returncode == 0:
            return text_response("Conectividad disponible.\n", 200)

        return text_response(
            "No se pudo confirmar la conectividad con el destino.\n", 200
        )
    finally:
        _concurrency_limit.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)