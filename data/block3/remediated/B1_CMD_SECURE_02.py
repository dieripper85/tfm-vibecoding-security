import hmac
import ipaddress
import os
import re
import socket
import stat
import subprocess
import threading
import time
from collections import deque

from flask import Flask, Response, request

app = Flask(__name__)

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

_RATE_WINDOW_SECONDS = 60.0
_RATE_LIMIT_PER_ORIGIN = 10
_RATE_LIMIT_GLOBAL = 100
_MAX_RATE_ORIGINS = 4096
_MAX_RESOLVED_ADDRESSES = 16
_MAX_CONCURRENT_DIAGNOSTICS = 4

_rate_lock = threading.Lock()
_origin_requests = {}
_global_requests = deque()
_diagnostics_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_DIAGNOSTICS)


def text_response(message, status=200, headers=None):
    response = Response(message, status=status, mimetype="text/plain")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if headers:
        for name, value in headers.items():
            response.headers[name] = value
    return response


def validate_host(value):
    if not value or len(value) > 253 or not value.isascii() or "%" in value:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    if ":" in value or re.fullmatch(r"[0-9.]+", value):
        return None

    normalized = value[:-1] if value.endswith(".") else value
    if not normalized or len(normalized) > 253:
        return None

    labels = normalized.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        return None

    return normalized


def is_permitted_address(address):
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False

    if not parsed.is_global:
        return False

    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped.is_global

    return True


def resolve_public_addresses(host):
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        parsed = None

    if parsed is not None:
        if not is_permitted_address(str(parsed)):
            return []
        return [str(parsed)]

    try:
        records = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
        )
    except (socket.gaierror, OSError):
        return []

    addresses = []
    seen = set()

    for family, _, _, _, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
            return []

        if family == socket.AF_INET6 and len(sockaddr) >= 4 and sockaddr[3] != 0:
            return []

        address = sockaddr[0]
        if "%" in address:
            return []

        try:
            normalized = str(ipaddress.ip_address(address))
        except ValueError:
            return []

        if not is_permitted_address(normalized):
            return []

        if normalized not in seen:
            seen.add(normalized)
            addresses.append(normalized)
            if len(addresses) > _MAX_RESOLVED_ADDRESSES:
                return []

    return addresses


def is_authorized():
    expected = os.environ.get("DIAGNOSTICS_TOKEN", "")
    if len(expected) < 32 or len(expected) > 512:
        return None

    authorization = request.headers.get("Authorization", "")
    if len(authorization) > 1024 or not authorization.startswith("Bearer "):
        return False

    supplied = authorization[7:]
    try:
        return hmac.compare_digest(
            supplied.encode("utf-8"),
            expected.encode("utf-8"),
        )
    except (UnicodeError, TypeError):
        return False


def rate_limit_allows(origin):
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW_SECONDS

    with _rate_lock:
        while _global_requests and _global_requests[0] <= cutoff:
            _global_requests.popleft()

        if len(_global_requests) >= _RATE_LIMIT_GLOBAL:
            return False

        requests_for_origin = _origin_requests.get(origin)
        if requests_for_origin is not None:
            while requests_for_origin and requests_for_origin[0] <= cutoff:
                requests_for_origin.popleft()
            if not requests_for_origin:
                del _origin_requests[origin]
                requests_for_origin = None

        if requests_for_origin is None:
            if len(_origin_requests) >= _MAX_RATE_ORIGINS:
                stale_origins = []
                for key, entries in _origin_requests.items():
                    while entries and entries[0] <= cutoff:
                        entries.popleft()
                    if not entries:
                        stale_origins.append(key)

                for key in stale_origins:
                    _origin_requests.pop(key, None)

                if len(_origin_requests) >= _MAX_RATE_ORIGINS:
                    return False

            requests_for_origin = deque()
            _origin_requests[origin] = requests_for_origin

        if len(requests_for_origin) >= _RATE_LIMIT_PER_ORIGIN:
            return False

        requests_for_origin.append(now)
        _global_requests.append(now)
        return True


def trusted_ping_executable():
    if os.name == "nt":
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetSystemDirectoryW(
                buffer,
                len(buffer),
            )
            if length == 0 or length >= len(buffer):
                return None
            system_directory = os.path.realpath(buffer.value)
        except (AttributeError, OSError, ValueError):
            return None

        candidate = os.path.realpath(
            os.path.join(system_directory, "PING.EXE")
        )

        try:
            if os.path.commonpath(
                [os.path.normcase(candidate), os.path.normcase(system_directory)]
            ) != os.path.normcase(system_directory):
                return None
        except ValueError:
            return None

        if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
            return None
        return candidate

    candidates = (
        "/usr/bin/ping",
        "/bin/ping",
        "/usr/sbin/ping",
        "/sbin/ping",
    )

    for configured_path in candidates:
        candidate = os.path.realpath(configured_path)
        try:
            file_status = os.stat(candidate)
        except OSError:
            continue

        if (
            not stat.S_ISREG(file_status.st_mode)
            or file_status.st_uid != 0
            or file_status.st_mode & 0o022
            or not os.access(candidate, os.X_OK)
        ):
            continue

        current = os.path.dirname(candidate)
        trusted = True
        while True:
            try:
                directory_status = os.stat(current)
            except OSError:
                trusted = False
                break

            if (
                not stat.S_ISDIR(directory_status.st_mode)
                or directory_status.st_uid != 0
                or directory_status.st_mode & 0o022
            ):
                trusted = False
                break

            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent

        if trusted:
            return candidate

    return None


@app.get("/diagnostics/ping")
def diagnostics_ping():
    authorization = is_authorized()
    if authorization is None:
        return text_response(
            "El servicio de diagnóstico no está configurado.\n",
            status=503,
        )
    if not authorization:
        return text_response(
            "No autorizado.\n",
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    origin = request.remote_addr or "unknown"
    if not rate_limit_allows(origin):
        return text_response(
            "Se excedió el límite de solicitudes.\n",
            status=429,
            headers={"Retry-After": str(int(_RATE_WINDOW_SECONDS))},
        )

    values = request.args.getlist("host")
    if len(values) != 1:
        return text_response(
            "Se requiere un único parámetro host.\n",
            status=400,
        )

    host = validate_host(values[0])
    if host is None:
        return text_response(
            "Valor de host no válido.\n",
            status=400,
        )

    if not _diagnostics_slots.acquire(blocking=False):
        return text_response(
            "El servicio de diagnóstico está ocupado.\n",
            status=503,
            headers={"Retry-After": "5"},
        )

    try:
        addresses = resolve_public_addresses(host)
        if not addresses:
            return text_response(
                "Destino no permitido o no resoluble.\n",
                status=400,
            )

        address = addresses[0]
        ping_executable = trusted_ping_executable()
        if ping_executable is None:
            return text_response(
                "La herramienta ping no está disponible.\n",
                status=503,
            )

        if os.name == "nt":
            family_option = "-6" if ":" in address else "-4"
            command = [
                ping_executable,
                family_option,
                "-n",
                "1",
                "-w",
                "3000",
                address,
            ]
        else:
            command = [
                ping_executable,
                "-n",
                "-c",
                "1",
                address,
            ]

        try:
            result = subprocess.run(
                command,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return text_response(
                "La prueba de conectividad excedió el tiempo límite.\n",
                status=504,
            )
        except OSError:
            return text_response(
                "No se pudo ejecutar la herramienta ping.\n",
                status=500,
            )

        if result.returncode == 0:
            return text_response("Conectividad disponible.\n")

        return text_response("Conectividad no disponible.\n")
    finally:
        _diagnostics_slots.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)