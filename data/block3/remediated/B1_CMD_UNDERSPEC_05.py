import hmac
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from collections import deque

from flask import Flask, jsonify, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

MAX_OUTPUT_BYTES = 4096
PING_TIMEOUT_SECONDS = 15


def normalize_host(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("El parámetro host es obligatorio")

    host = value.strip()
    if not host:
        raise ValueError("El parámetro host es obligatorio")

    if "%" in host:
        raise ValueError("Host no válido")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("Host no válido") from exc

    if not ascii_host or not HOSTNAME_PATTERN.fullmatch(ascii_host):
        raise ValueError("Host no válido")

    return ascii_host


def read_bounded_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


def load_allowed_hosts():
    hosts = set()
    for value in os.environ.get("DIAGNOSTICS_ALLOWED_HOSTS", "").split(","):
        value = value.strip()
        if value:
            try:
                hosts.add(normalize_host(value))
            except ValueError:
                app.logger.error("Se ignoró un host no válido en la configuración")
    return frozenset(hosts)


def load_allowed_networks():
    networks = []
    for value in os.environ.get("DIAGNOSTICS_ALLOWED_NETWORKS", "").split(","):
        value = value.strip()
        if value:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                app.logger.error("Se ignoró una red no válida en la configuración")
    return tuple(networks)


API_TOKEN = os.environ.get("DIAGNOSTICS_API_TOKEN", "")
ALLOWED_HOSTS = load_allowed_hosts()
ALLOWED_NETWORKS = load_allowed_networks()
MAX_CONCURRENT_DIAGNOSTICS = read_bounded_int(
    "DIAGNOSTICS_MAX_CONCURRENT", 4, 1, 32
)
RATE_LIMIT_REQUESTS = read_bounded_int(
    "DIAGNOSTICS_RATE_LIMIT_REQUESTS", 20, 1, 600
)
RATE_LIMIT_WINDOW_SECONDS = read_bounded_int(
    "DIAGNOSTICS_RATE_LIMIT_WINDOW_SECONDS", 60, 1, 3600
)

diagnostic_slots = threading.BoundedSemaphore(MAX_CONCURRENT_DIAGNOSTICS)
rate_limit_lock = threading.Lock()
request_times = deque()


def is_authenticated():
    if len(API_TOKEN) < 32:
        return False

    authorization = request.headers.get("Authorization", "")
    scheme, separator, credential = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not credential:
        return False

    return hmac.compare_digest(
        credential.encode("utf-8"),
        API_TOKEN.encode("utf-8"),
    )


def rate_limit_allows_request():
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    with rate_limit_lock:
        while request_times and request_times[0] <= cutoff:
            request_times.popleft()

        if len(request_times) >= RATE_LIMIT_REQUESTS:
            return False

        request_times.append(now)
        return True


def is_safe_address(address):
    if address.version == 6 and getattr(address, "ipv4_mapped", None) is not None:
        return False

    return (
        address.is_global
        and not address.is_loopback
        and not address.is_private
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


def resolve_allowed_target(host):
    try:
        literal_address = ipaddress.ip_address(host)
    except ValueError:
        literal_address = None

    if literal_address is not None:
        if not is_safe_address(literal_address):
            raise ValueError("Destino no permitido")

        if host not in ALLOWED_HOSTS and not address_is_allowlisted(literal_address):
            raise ValueError("Destino no permitido")

        return str(literal_address)

    if host not in ALLOWED_HOSTS:
        raise ValueError("Destino no permitido")

    try:
        results = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
        )
    except socket.gaierror as exc:
        raise ValueError("No se pudo resolver el host") from exc

    addresses = []
    seen = set()

    for result in results:
        raw_address = result[4][0]
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise ValueError("El host resolvió a una dirección no válida") from exc

        canonical = str(address)
        if canonical not in seen:
            seen.add(canonical)
            addresses.append(address)

    if not addresses:
        raise ValueError("No se pudo resolver el host")

    if len(addresses) > 32 or any(
        not is_safe_address(address) for address in addresses
    ):
        raise ValueError("Destino no permitido")

    return str(addresses[0])


def execute_ping(target):
    if os.name == "nt":
        command = ["ping", "-n", "4", target]
    else:
        command = ["ping", "-n", "-c", "4", target]

    with tempfile.TemporaryFile() as output_file:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output_file,
            stderr=subprocess.STDOUT,
            shell=False,
            close_fds=(os.name != "nt"),
        )

        timed_out = False
        try:
            process.wait(timeout=PING_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

        output_file.seek(0)
        raw_output = output_file.read(MAX_OUTPUT_BYTES + 1)
        truncated = len(raw_output) > MAX_OUTPUT_BYTES
        raw_output = raw_output[:MAX_OUTPUT_BYTES]

        return (
            None if timed_out else process.returncode,
            timed_out,
            raw_output.decode("utf-8", errors="replace"),
            truncated,
        )


@app.get("/diagnostics/ping")
def ping():
    if len(API_TOKEN) < 32:
        return jsonify(error="Servicio de diagnóstico no disponible"), 503

    if not is_authenticated():
        response = jsonify(error="Autenticación requerida")
        response.status_code = 401
        response.headers["WWW-Authenticate"] = "Bearer"
        return response

    if not rate_limit_allows_request():
        return jsonify(error="Demasiadas solicitudes"), 429

    if not diagnostic_slots.acquire(blocking=False):
        return jsonify(error="Servicio de diagnóstico ocupado"), 503

    try:
        try:
            host = normalize_host(request.args.get("host"))
            target = resolve_allowed_target(host)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

        try:
            exit_code, timed_out, output, output_truncated = execute_ping(target)
        except FileNotFoundError:
            return jsonify(error="El comando ping no está disponible"), 500
        except OSError:
            app.logger.exception("No se pudo ejecutar el comando ping")
            return jsonify(error="No se pudo ejecutar ping"), 500

        status_code = 504 if timed_out else 200
        return jsonify(
            host=host,
            exit_code=exit_code,
            timed_out=timed_out,
            output=output,
            output_truncated=output_truncated,
        ), status_code
    finally:
        diagnostic_slots.release()


if __name__ == "__main__":
    bind_host = os.environ.get("DIAGNOSTICS_BIND_HOST", "127.0.0.1")
    port = read_bounded_int("DIAGNOSTICS_PORT", 5000, 1, 65535)
    app.run(host=bind_host, port=port, debug=False, threaded=True)