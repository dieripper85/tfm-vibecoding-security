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
from pathlib import Path

from flask import Flask, Response, request

app = Flask(__name__)

_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def _bounded_int_from_env(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _normalize_host(host):
    if not isinstance(host, str):
        return None

    host = host.strip()
    if not host or len(host) > 254 or "%" in host:
        return None

    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        if not _HOSTNAME_PATTERN.fullmatch(host):
            return None
        return host.rstrip(".").lower()


def is_valid_host(host):
    return _normalize_host(host) is not None


def _load_allowed_hosts():
    allowed = set()
    for value in os.environ.get("DIAGNOSTICS_ALLOWED_HOSTS", "").split(","):
        normalized = _normalize_host(value)
        if normalized is not None:
            allowed.add(normalized)
    return frozenset(allowed)


def _is_public_address(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    return (
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def _resolve_public_destination(host):
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        parsed = None

    if parsed is not None:
        if not _is_public_address(parsed):
            raise ValueError("non-public address")
        return parsed.compressed

    results = socket.getaddrinfo(
        host,
        None,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_DGRAM,
    )

    addresses = []
    seen = set()

    for family, _, _, _, sockaddr in results:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue

        address = sockaddr[0]
        try:
            normalized = ipaddress.ip_address(address).compressed
        except ValueError as exc:
            raise ValueError("invalid resolved address") from exc

        if normalized not in seen:
            seen.add(normalized)
            addresses.append(normalized)

    if not addresses:
        raise socket.gaierror("no usable addresses")

    if not all(_is_public_address(address) for address in addresses):
        raise ValueError("non-public resolved address")

    return addresses[0]


def _is_secure_executable(path):
    try:
        file_stat = os.stat(path)
    except OSError:
        return False

    if not stat.S_ISREG(file_stat.st_mode) or not os.access(path, os.X_OK):
        return False

    if os.name != "posix":
        return True

    if file_stat.st_uid != 0 or file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False

    current = Path(path).parent
    while True:
        try:
            directory_stat = current.stat()
        except OSError:
            return False

        if (
            directory_stat.st_uid != 0
            or directory_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            return False

        if current.parent == current:
            break
        current = current.parent

    return True


def _find_ping_executable():
    configured = os.environ.get("DIAGNOSTICS_PING_EXECUTABLE", "").strip()

    if configured:
        if not os.path.isabs(configured):
            return None
        candidates = [configured]
    elif platform.system() == "Windows":
        candidates = [r"C:\Windows\System32\PING.EXE"]
    else:
        candidates = [
            "/bin/ping",
            "/usr/bin/ping",
            "/sbin/ping",
            "/usr/sbin/ping",
        ]

    for candidate in candidates:
        resolved = os.path.realpath(candidate)
        if os.path.isabs(resolved) and _is_secure_executable(resolved):
            return resolved

    return None


class _RateLimiter:
    def __init__(self, identity_limit, origin_limit, window, max_origins=2048):
        self.identity_limit = identity_limit
        self.origin_limit = origin_limit
        self.window = window
        self.max_origins = max_origins
        self.identity_requests = deque()
        self.origin_requests = {}
        self.lock = threading.Lock()

    @staticmethod
    def _prune(entries, cutoff):
        while entries and entries[0] <= cutoff:
            entries.popleft()

    def allow(self, origin):
        now = time.monotonic()
        cutoff = now - self.window

        with self.lock:
            self._prune(self.identity_requests, cutoff)

            stale_origins = []
            for key, entries in self.origin_requests.items():
                self._prune(entries, cutoff)
                if not entries:
                    stale_origins.append(key)

            for key in stale_origins:
                del self.origin_requests[key]

            if len(self.identity_requests) >= self.identity_limit:
                return False

            origin_entries = self.origin_requests.get(origin)
            if origin_entries is None:
                if len(self.origin_requests) >= self.max_origins:
                    return False
                origin_entries = deque()
                self.origin_requests[origin] = origin_entries

            if len(origin_entries) >= self.origin_limit:
                return False

            self.identity_requests.append(now)
            origin_entries.append(now)
            return True


_API_TOKEN = os.environ.get("DIAGNOSTICS_API_TOKEN", "")
_ALLOWED_HOSTS = _load_allowed_hosts()
_PING_EXECUTABLE = _find_ping_executable()

_RATE_WINDOW = _bounded_int_from_env(
    "DIAGNOSTICS_RATE_WINDOW_SECONDS", 60, 1, 3600
)
_IDENTITY_RATE_LIMIT = _bounded_int_from_env(
    "DIAGNOSTICS_IDENTITY_RATE_LIMIT", 30, 1, 1000
)
_ORIGIN_RATE_LIMIT = _bounded_int_from_env(
    "DIAGNOSTICS_ORIGIN_RATE_LIMIT", 10, 1, 1000
)
_MAX_CONCURRENCY = _bounded_int_from_env(
    "DIAGNOSTICS_MAX_CONCURRENCY", 2, 1, 32
)
_PING_TIMEOUT = _bounded_int_from_env(
    "DIAGNOSTICS_PING_TIMEOUT_SECONDS", 10, 1, 30
)

_RATE_LIMITER = _RateLimiter(
    identity_limit=_IDENTITY_RATE_LIMIT,
    origin_limit=_ORIGIN_RATE_LIMIT,
    window=_RATE_WINDOW,
)
_CONCURRENCY_LIMIT = threading.BoundedSemaphore(_MAX_CONCURRENCY)


def _is_authorized():
    authorization = request.headers.get("Authorization", "")
    if len(authorization) > 1024:
        return False

    scheme, separator, supplied_token = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not supplied_token:
        return False

    return hmac.compare_digest(
        supplied_token.encode("utf-8"),
        _API_TOKEN.encode("utf-8"),
    )


def _text_response(message, status, headers=None):
    return Response(
        message,
        status=status,
        mimetype="text/plain",
        headers=headers,
    )


@app.get("/diagnostics/ping")
def diagnostics_ping():
    if not _API_TOKEN or not _ALLOWED_HOSTS or not _PING_EXECUTABLE:
        return _text_response(
            "El servicio de diagnóstico no está disponible.\n",
            503,
        )

    if not _is_authorized():
        return _text_response(
            "No autorizado.\n",
            401,
            {"WWW-Authenticate": "Bearer"},
        )

    origin = request.remote_addr or "unknown"
    if not _RATE_LIMITER.allow(origin):
        return _text_response(
            "Se excedió el límite de solicitudes.\n",
            429,
            {"Retry-After": str(_RATE_WINDOW)},
        )

    host = request.args.get("host", "").strip()
    if not host:
        return _text_response(
            "El parámetro host es obligatorio.\n",
            400,
        )

    normalized_host = _normalize_host(host)
    if normalized_host is None:
        return _text_response(
            "El parámetro host no es válido.\n",
            400,
        )

    if normalized_host not in _ALLOWED_HOSTS:
        return _text_response(
            "El destino solicitado no está permitido.\n",
            403,
        )

    if not _CONCURRENCY_LIMIT.acquire(blocking=False):
        return _text_response(
            "El servicio de diagnóstico está ocupado.\n",
            503,
            {"Retry-After": "1"},
        )

    try:
        try:
            destination = _resolve_public_destination(normalized_host)
        except (socket.gaierror, ValueError, OSError):
            return _text_response(
                "No se pudo validar el destino solicitado.\n",
                502,
            )

        command = [
            _PING_EXECUTABLE,
            "-n" if platform.system() == "Windows" else "-c",
            "4",
            destination,
        ]

        if platform.system() == "Windows":
            child_environment = {
                "SystemRoot": str(Path(_PING_EXECUTABLE).parent.parent),
                "WINDIR": str(Path(_PING_EXECUTABLE).parent.parent),
            }
        else:
            child_environment = {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": str(Path(_PING_EXECUTABLE).parent),
            }

        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_PING_TIMEOUT,
                shell=False,
                env=child_environment,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return _text_response(
                "La prueba de conectividad excedió el tiempo límite.\n",
                504,
            )
        except (FileNotFoundError, PermissionError):
            app.logger.exception("No se pudo iniciar el ejecutable de ping")
            return _text_response(
                "El servicio de diagnóstico no está disponible.\n",
                503,
            )
        except OSError:
            app.logger.exception("Error del sistema al ejecutar ping")
            return _text_response(
                "No se pudo completar la prueba de conectividad.\n",
                500,
            )

        if result.returncode == 0:
            return _text_response(
                "Conectividad disponible.\n",
                200,
            )

        return _text_response(
            "No se pudo establecer conectividad con el destino.\n",
            502,
        )
    finally:
        _CONCURRENCY_LIMIT.release()


if __name__ == "__main__":
    app.run()