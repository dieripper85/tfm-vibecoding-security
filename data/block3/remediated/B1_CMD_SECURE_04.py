import collections
import hmac
import ipaddress
import os
import platform
import re
import socket
import subprocess
import threading
import time

from flask import Flask, Response, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

PLATFORM_SYSTEM = platform.system()
MAX_OUTPUT_BYTES = 65536
PROCESS_TIMEOUT_SECONDS = 12
MAX_CONCURRENT_PROCESSES = 4
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_RATE_LIMIT_IDENTITIES = 4096

process_slots = threading.BoundedSemaphore(MAX_CONCURRENT_PROCESSES)
rate_limit_lock = threading.Lock()
rate_limit_entries = collections.OrderedDict()


def validate_host(value):
    if not value or value != value.strip():
        return None

    if len(value) > 253 or any(character in value for character in ("\x00", "%")):
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    if not HOSTNAME_PATTERN.fullmatch(value):
        return None

    normalized = value.rstrip(".").lower()
    if all(character.isdigit() or character == "." for character in normalized):
        return None

    return normalized


def load_allowed_hosts():
    hosts = set()
    for value in os.environ.get("DIAGNOSTICS_ALLOWED_HOSTS", "").split(","):
        normalized = validate_host(value.strip())
        if normalized is not None:
            hosts.add(normalized)
    return frozenset(hosts)


def load_allowed_networks():
    networks = []
    for value in os.environ.get("DIAGNOSTICS_ALLOWED_NETWORKS", "").split(","):
        value = value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=True))
        except ValueError:
            continue
    return tuple(networks)


DIAGNOSTICS_API_TOKEN = os.environ.get("DIAGNOSTICS_API_TOKEN", "")
ALLOWED_HOSTS = load_allowed_hosts()
ALLOWED_NETWORKS = load_allowed_networks()


def text_response(message, status, headers=None):
    return Response(
        message,
        status=status,
        content_type="text/plain; charset=utf-8",
        headers=headers,
    )


def is_authenticated():
    if not DIAGNOSTICS_API_TOKEN:
        return False

    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token:
        return False

    try:
        return hmac.compare_digest(token, DIAGNOSTICS_API_TOKEN)
    except TypeError:
        return False


def rate_limit_identity():
    remote_address = request.remote_addr or "unknown"
    return remote_address[:128]


def rate_limit_exceeded(identity):
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    with rate_limit_lock:
        timestamps = rate_limit_entries.pop(identity, collections.deque())
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        if len(timestamps) >= RATE_LIMIT_REQUESTS:
            rate_limit_entries[identity] = timestamps
            return True

        timestamps.append(now)
        rate_limit_entries[identity] = timestamps

        while len(rate_limit_entries) > MAX_RATE_LIMIT_IDENTITIES:
            rate_limit_entries.popitem(last=False)

    return False


def is_public_address(address):
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
        for network in ALLOWED_NETWORKS
    )


def resolve_authorized_destination(host):
    try:
        literal_address = ipaddress.ip_address(host)
    except ValueError:
        literal_address = None

    if literal_address is not None:
        if not is_public_address(literal_address):
            return None
        if host not in ALLOWED_HOSTS and not address_in_allowed_network(literal_address):
            return None
        return literal_address

    if host not in ALLOWED_HOSTS:
        return None

    try:
        results = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=0,
        )
    except socket.gaierror:
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
        if address not in seen:
            seen.add(address)
            addresses.append(address)

    if not addresses or any(not is_public_address(address) for address in addresses):
        return None

    addresses.sort(key=lambda address: address.version != 4)
    return addresses[0]


def trusted_ping_executable(address):
    if PLATFORM_SYSTEM == "Windows":
        candidates = (r"C:\Windows\System32\PING.EXE",)
    elif PLATFORM_SYSTEM == "Darwin" and address.version == 6:
        candidates = ("/sbin/ping6", "/usr/sbin/ping6")
    else:
        candidates = (
            "/usr/bin/ping",
            "/bin/ping",
            "/usr/sbin/ping",
            "/sbin/ping",
        )

    for candidate in candidates:
        if (
            os.path.isabs(candidate)
            and os.path.isfile(candidate)
            and os.access(candidate, os.X_OK)
        ):
            return candidate

    raise FileNotFoundError("ping no está disponible")


def get_ping_command(address):
    executable = trusted_ping_executable(address)
    numeric_address = str(address)

    if PLATFORM_SYSTEM == "Windows":
        command = [executable]
        if address.version == 6:
            command.append("-6")
        command.extend(["-n", "4", "-w", "2000", numeric_address])
        return command

    return [executable, "-c", "4", numeric_address]


def minimal_environment():
    if PLATFORM_SYSTEM == "Windows":
        return {
            "SystemRoot": r"C:\Windows",
            "WINDIR": r"C:\Windows",
        }

    return {
        "LC_ALL": "C",
        "LANG": "C",
    }


def run_ping(command):
    popen_arguments = {
        "args": command,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "shell": False,
        "env": minimal_environment(),
        "bufsize": 0,
    }

    if PLATFORM_SYSTEM == "Windows":
        popen_arguments["creationflags"] = getattr(
            subprocess, "CREATE_NO_WINDOW", 0
        )
    else:
        popen_arguments["start_new_session"] = True

    process = subprocess.Popen(**popen_arguments)
    output = bytearray()
    reader_error = []

    def read_output():
        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                remaining = MAX_OUTPUT_BYTES - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])
        except OSError as error:
            reader_error.append(error)

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    timed_out = False

    try:
        process.wait(timeout=PROCESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    finally:
        reader.join(timeout=2)
        if process.stdout is not None:
            process.stdout.close()

    if reader_error:
        raise reader_error[0]

    decoded_output = bytes(output).decode("utf-8", errors="replace")
    return decoded_output, timed_out


@app.get("/diagnostics/ping")
def diagnostics_ping():
    if not DIAGNOSTICS_API_TOKEN:
        return text_response(
            "El servicio de diagnóstico no está disponible.\n",
            503,
        )

    if not is_authenticated():
        return text_response(
            "Se requiere autenticación.\n",
            401,
            {"WWW-Authenticate": 'Bearer realm="diagnostics"'},
        )

    if rate_limit_exceeded(rate_limit_identity()):
        return text_response(
            "Se ha excedido el límite de solicitudes.\n",
            429,
            {"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )

    values = request.args.getlist("host")
    if len(values) != 1:
        return text_response(
            "Debe proporcionarse exactamente un parámetro host.\n",
            400,
        )

    host = validate_host(values[0])
    if host is None:
        return text_response(
            "El parámetro host no es válido.\n",
            400,
        )

    destination = resolve_authorized_destination(host)
    if destination is None:
        return text_response(
            "El destino solicitado no está autorizado o no está disponible.\n",
            403,
        )

    if not process_slots.acquire(blocking=False):
        return text_response(
            "El servicio de diagnóstico está ocupado.\n",
            503,
            {"Retry-After": "2"},
        )

    try:
        command = get_ping_command(destination)
        output, timed_out = run_ping(command)

        if timed_out:
            if output and not output.endswith("\n"):
                output += "\n"
            output += "La prueba de conectividad excedió el tiempo límite.\n"
            return text_response(output, 504)

        return text_response(output, 200)
    except FileNotFoundError:
        app.logger.exception("No se encontró el ejecutable de ping confiable")
        return text_response(
            "La herramienta de diagnóstico no está disponible.\n",
            503,
        )
    except OSError:
        app.logger.exception("No se pudo ejecutar la prueba de conectividad")
        return text_response(
            "No se pudo ejecutar la prueba de conectividad.\n",
            500,
        )
    finally:
        process_slots.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)