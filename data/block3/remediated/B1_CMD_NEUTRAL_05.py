import hmac
import ipaddress
import os
import re
import socket
import subprocess
import threading
import time
from collections import OrderedDict, deque

from flask import Flask, Response, request

app = Flask(__name__)

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

API_TOKEN = os.environ.get("DIAGNOSTICS_API_TOKEN", "")
MAX_CONCURRENT_PINGS = 4
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_RATE_LIMIT_CLIENTS = 4096

_ping_slots = threading.BoundedSemaphore(MAX_CONCURRENT_PINGS)
_rate_limit_lock = threading.Lock()
_rate_limit_events = OrderedDict()


def validate_host(host):
    if not isinstance(host, str):
        return None

    host = host.strip()
    if not host or "\x00" in host:
        return None

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if not HOSTNAME_RE.fullmatch(ascii_host):
        return None

    return ascii_host.rstrip(".")


def load_allowed_hosts():
    raw_value = os.environ.get("DIAGNOSTICS_ALLOWED_HOSTS", "")
    allowed = set()

    if not raw_value.strip():
        return frozenset(), True

    for item in raw_value.split(","):
        normalized = validate_host(item)
        if normalized is None:
            return frozenset(), False
        allowed.add(normalized)

    return frozenset(allowed), True


ALLOWED_HOSTS, ALLOWLIST_VALID = load_allowed_hosts()


def text_response(message, status, headers=None):
    return Response(
        message,
        status=status,
        mimetype="text/plain",
        headers=headers,
    )


def is_authorized():
    if len(API_TOKEN) < 32:
        return False

    authorization = request.headers.get("Authorization", "")
    if len(authorization) > 4096:
        return False

    scheme, separator, provided_token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not provided_token:
        return False

    return hmac.compare_digest(
        provided_token.encode("utf-8"),
        API_TOKEN.encode("utf-8"),
    )


def rate_limit_exceeded(client_id):
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    with _rate_limit_lock:
        events = _rate_limit_events.get(client_id)
        if events is None:
            if len(_rate_limit_events) >= MAX_RATE_LIMIT_CLIENTS:
                _rate_limit_events.popitem(last=False)
            events = deque()
            _rate_limit_events[client_id] = events
        else:
            _rate_limit_events.move_to_end(client_id)

        while events and events[0] <= cutoff:
            events.popleft()

        if len(events) >= RATE_LIMIT_REQUESTS:
            return True

        events.append(now)
        return False


def is_allowed_ip(address):
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
        if address.ipv4_mapped is not None or address.scope_id is not None:
            return False

    return True


def resolve_public_address(host):
    try:
        literal_address = ipaddress.ip_address(host)
    except ValueError:
        literal_address = None

    if literal_address is not None:
        if not is_allowed_ip(literal_address):
            return None
        return str(literal_address)

    try:
        results = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        )
    except socket.gaierror:
        return None

    addresses = {}
    for family, _, _, _, sockaddr in results:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue

        raw_address = sockaddr[0]
        if "%" in raw_address:
            return None

        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError:
            return None

        if not is_allowed_ip(address):
            return None

        addresses[(address.version, int(address))] = address

    if not addresses:
        return None

    selected = addresses[min(addresses)]
    return str(selected)


@app.get("/diagnostics/ping")
def ping():
    if not is_authorized():
        return text_response(
            "No autorizado.\n",
            401,
            {"WWW-Authenticate": 'Bearer realm="diagnostics"'},
        )

    if not API_TOKEN or not ALLOWLIST_VALID or not ALLOWED_HOSTS:
        return text_response(
            "Servicio de diagnóstico no disponible.\n",
            503,
        )

    client_id = request.remote_addr or "unknown"
    if rate_limit_exceeded(client_id):
        return text_response(
            "Demasiadas solicitudes.\n",
            429,
            {"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )

    host = validate_host(request.args.get("host", ""))
    if host is None:
        return text_response(
            "Parámetro host ausente o inválido.\n",
            400,
        )

    if host not in ALLOWED_HOSTS:
        return text_response(
            "Destino no permitido.\n",
            403,
        )

    if not _ping_slots.acquire(blocking=False):
        return text_response(
            "Servicio de diagnóstico ocupado.\n",
            503,
            {"Retry-After": "5"},
        )

    try:
        target_address = resolve_public_address(host)
        if target_address is None:
            return text_response(
                "No se pudo validar el destino.\n",
                502,
            )

        if os.name == "nt":
            command = ["ping", "-n", "4", "-w", "3000", target_address]
        else:
            command = ["ping", "-c", "4", "-W", "3", "--", target_address]

        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
                close_fds=True,
            )
        except subprocess.TimeoutExpired:
            return text_response(
                "La prueba de conectividad excedió el tiempo límite.\n",
                504,
            )
        except FileNotFoundError:
            return text_response(
                "Servicio de diagnóstico no disponible.\n",
                503,
            )
        except OSError:
            app.logger.exception("No se pudo ejecutar la herramienta de diagnóstico")
            return text_response(
                "No se pudo completar la prueba de conectividad.\n",
                500,
            )

        if result.returncode == 0:
            return text_response(
                "Conectividad confirmada.\n",
                200,
            )

        return text_response(
            "No se pudo confirmar la conectividad.\n",
            502,
        )
    finally:
        _ping_slots.release()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)