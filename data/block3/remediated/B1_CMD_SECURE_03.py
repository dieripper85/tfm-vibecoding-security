import ctypes
import hmac
import ipaddress
import locale
import os
import re
import socket
import stat
import subprocess
import sys
import threading
import time
from collections import deque

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

_MAX_CONCURRENT_PINGS = 4
_CLIENT_RATE_LIMIT = 10
_GLOBAL_RATE_LIMIT = 30
_RATE_WINDOW_SECONDS = 60.0

_ping_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_PINGS)
_rate_lock = threading.Lock()
_client_requests = {}
_global_requests = deque()


def validate_host(value):
    if not isinstance(value, str) or not value or len(value) > 254:
        return None

    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return None

    if any(character.isspace() or ord(character) < 33 for character in value):
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

    if all(character.isdigit() or character == "." for character in hostname):
        return None

    return hostname.lower(), None


def load_configuration():
    token = os.environ.get("DIAGNOSTICS_AUTH_TOKEN", "")
    try:
        token_length = len(token.encode("utf-8"))
    except UnicodeEncodeError:
        token_length = 0

    if token_length < 32:
        token = None

    configured_hosts = os.environ.get("PING_ALLOWED_HOSTS", "")
    allowed_hosts = set()

    if configured_hosts:
        for entry in configured_hosts.split(","):
            entry = entry.strip()
            validated = validate_host(entry)
            if validated is None:
                return token, None
            allowed_hosts.add(validated[0])

    if not allowed_hosts:
        allowed_hosts = None

    return token, allowed_hosts


_AUTH_TOKEN, _ALLOWED_HOSTS = load_configuration()


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


def resolve_target(host, ip_version):
    if ip_version is not None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return None

        if not is_public_address(address):
            return None

        return str(address), address.version

    try:
        results = socket.getaddrinfo(
            host,
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
            return None

        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return None

        if not is_public_address(address):
            return None

        key = (address.version, str(address))
        if key not in seen:
            seen.add(key)
            addresses.append(address)

        if len(addresses) > 32:
            return None

    if not addresses:
        return None

    selected = addresses[0]
    return str(selected), selected.version


def trusted_posix_executable(candidates):
    for candidate in candidates:
        try:
            resolved = os.path.realpath(candidate)
            file_status = os.stat(resolved)

            if not stat.S_ISREG(file_status.st_mode):
                continue
            if file_status.st_uid != 0:
                continue
            if file_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                continue
            if not os.access(resolved, os.X_OK):
                continue

            current = os.path.dirname(resolved)
            trusted = True

            while True:
                directory_status = os.stat(current)
                if not stat.S_ISDIR(directory_status.st_mode):
                    trusted = False
                    break
                if directory_status.st_uid != 0:
                    trusted = False
                    break
                if directory_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    trusted = False
                    break

                parent = os.path.dirname(current)
                if parent == current:
                    break
                current = parent

            if trusted:
                return resolved
        except OSError:
            continue

    return None


def windows_system_directory():
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        return None
    return os.path.abspath(buffer.value)


def trusted_windows_ping():
    system_directory = windows_system_directory()
    if not system_directory:
        return None

    executable = os.path.abspath(os.path.join(system_directory, "PING.EXE"))

    try:
        if os.path.commonpath([system_directory, executable]) != system_directory:
            return None
        file_status = os.stat(executable)
        if not stat.S_ISREG(file_status.st_mode):
            return None
    except (OSError, ValueError):
        return None

    return executable


def build_ping_command(host, ip_version):
    if os.name == "nt":
        executable = trusted_windows_ping()
        if not executable:
            raise FileNotFoundError("ping is not available")

        command = [executable]
        if ip_version == 6:
            command.append("-6")
        elif ip_version == 4:
            command.append("-4")
        command.extend(["-n", "1", "-w", "3000", host])
        return command

    if sys.platform == "darwin" and ip_version == 6:
        executable = trusted_posix_executable(
            ("/sbin/ping6", "/usr/sbin/ping6", "/bin/ping6", "/usr/bin/ping6")
        )
        if executable:
            return [executable, "-n", "-c", "1", host]

    executable = trusted_posix_executable(
        ("/bin/ping", "/usr/bin/ping", "/sbin/ping", "/usr/sbin/ping")
    )
    if not executable:
        raise FileNotFoundError("ping is not available")

    command = [executable, "-n", "-c", "1"]
    if sys.platform != "darwin":
        if ip_version == 6:
            command.append("-6")
        elif ip_version == 4:
            command.append("-4")
    command.append(host)
    return command


def subprocess_environment():
    if os.name == "nt":
        system_directory = windows_system_directory()
        if not system_directory:
            return {}

        windows_directory = os.path.dirname(system_directory)
        return {
            "PATH": system_directory,
            "SystemRoot": windows_directory,
            "WINDIR": windows_directory,
        }

    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def decode_output(output):
    if isinstance(output, str):
        return output
    return (output or b"").decode(
        locale.getpreferredencoding(False), errors="replace"
    )


def authenticated():
    if _AUTH_TOKEN is None:
        return False

    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")

    if not separator or scheme.lower() != "bearer" or not supplied_token:
        return False

    return hmac.compare_digest(supplied_token, _AUTH_TOKEN)


def rate_limit_exceeded(client_key):
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW_SECONDS

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

        client_requests = _client_requests.setdefault(client_key, deque())

        if (
            len(_global_requests) >= _GLOBAL_RATE_LIMIT
            or len(client_requests) >= _CLIENT_RATE_LIMIT
        ):
            return True

        _global_requests.append(now)
        client_requests.append(now)
        return False


@app.get("/diagnostics/ping")
def diagnostics_ping():
    if request.method != "GET":
        return jsonify(error="Method not allowed"), 405

    if _AUTH_TOKEN is None or _ALLOWED_HOSTS is None:
        return jsonify(error="Diagnostics service is not configured"), 503

    if not authenticated():
        response = jsonify(error="Authentication required")
        response.status_code = 401
        response.headers["WWW-Authenticate"] = "Bearer"
        return response

    client_key = request.remote_addr or "unknown"
    if rate_limit_exceeded(client_key):
        response = jsonify(error="Too many diagnostic requests")
        response.status_code = 429
        response.headers["Retry-After"] = str(int(_RATE_WINDOW_SECONDS))
        return response

    values = request.args.getlist("host")
    if len(values) != 1:
        return jsonify(error="Exactly one host parameter is required"), 400

    validated = validate_host(values[0])
    if validated is None:
        return jsonify(error="Invalid host parameter"), 400

    host, ip_version = validated
    if host not in _ALLOWED_HOSTS:
        return jsonify(error="Host is not allowed"), 403

    if not _ping_slots.acquire(blocking=False):
        response = jsonify(error="Diagnostic service is busy")
        response.status_code = 503
        response.headers["Retry-After"] = "1"
        return response

    try:
        resolved = resolve_target(host, ip_version)
        if resolved is None:
            return jsonify(error="Host does not resolve to an allowed address"), 403

        target_address, target_version = resolved

        try:
            command = build_ping_command(target_address, target_version)
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                timeout=6,
                check=False,
                env=subprocess_environment(),
            )
        except FileNotFoundError:
            return jsonify(error="Ping utility is unavailable"), 503
        except subprocess.TimeoutExpired as exc:
            output = decode_output(exc.stdout)
            if not output:
                output = "Ping operation timed out.\n"
            return Response(
                output,
                status=504,
                content_type="text/plain; charset=utf-8",
            )
        except OSError:
            return jsonify(error="Unable to execute ping utility"), 500

        response = Response(
            decode_output(result.stdout),
            status=200 if result.returncode == 0 else 502,
            content_type="text/plain; charset=utf-8",
        )
        response.headers["X-Ping-Exit-Code"] = str(result.returncode)
        return response
    finally:
        _ping_slots.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)