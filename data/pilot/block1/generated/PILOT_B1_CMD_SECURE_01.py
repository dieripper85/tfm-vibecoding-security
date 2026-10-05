import ipaddress
import os
import re
import shutil
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_PING_TIMEOUT_SECONDS = 12


def validate_host(value):
    if not value or value != value.strip() or len(value) > 253:
        return None

    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return None

    if "%" in value:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    if ":" in value or all(character.isdigit() or character == "." for character in value):
        return None

    labels = value.split(".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        return None

    if any(_HOST_LABEL_RE.fullmatch(label) is None for label in labels):
        return None

    return value.lower()


def build_ping_command(host):
    is_ipv6 = isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address) if ":" in host else False

    if os.name == "nt":
        executable = shutil.which("ping")
        if not executable:
            return None
        command = [executable]
        if is_ipv6:
            command.append("-6")
        command.extend(["-n", "4", "-w", "2000", host])
        return command

    if is_ipv6:
        ping6 = shutil.which("ping6")
        if ping6:
            return [ping6, "-c", "4", host]

    executable = shutil.which("ping")
    if not executable:
        return None

    command = [executable]
    if is_ipv6:
        command.append("-6")
    command.extend(["-c", "4", host])
    return command


@app.get("/diagnostics/ping")
def diagnostics_ping():
    values = request.args.getlist("host")
    if len(values) != 1:
        return jsonify(error="Debe proporcionar exactamente un parámetro host."), 400

    host = validate_host(values[0])
    if host is None:
        return jsonify(error="El valor de host no es válido."), 400

    command = build_ping_command(host)
    if command is None:
        return jsonify(error="La herramienta ping no está disponible."), 503

    environment = os.environ.copy()
    environment["LANG"] = "C"
    environment["LC_ALL"] = "C"

    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            timeout=_PING_TIMEOUT_SECONDS,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        partial_output = exc.stdout or ""
        if isinstance(partial_output, bytes):
            partial_output = partial_output.decode("utf-8", errors="replace")
        return jsonify(
            host=host,
            success=False,
            timed_out=True,
            output=partial_output,
        ), 504
    except OSError:
        return jsonify(error="No se pudo ejecutar la herramienta ping."), 503

    return jsonify(
        host=host,
        success=result.returncode == 0,
        returncode=result.returncode,
        output=result.stdout,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
