import ipaddress
import locale
import os
import re
import shutil
import subprocess
import sys

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_host(value):
    if not value or len(value) > 254:
        return None

    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return None

    if any(character.isspace() or ord(character) < 33 for character in value):
        return None

    try:
        address = ipaddress.ip_address(value)
        return value, address.version
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

    return value, None


def build_ping_command(host, ip_version):
    if os.name == "nt":
        executable = shutil.which("ping")
        if not executable:
            raise FileNotFoundError("ping is not available")
        command = [executable]
        if ip_version == 6:
            command.append("-6")
        elif ip_version == 4:
            command.append("-4")
        command.extend(["-n", "1", "-w", "3000", host])
        return command

    executable = None
    if sys.platform == "darwin" and ip_version == 6:
        executable = shutil.which("ping6")

    if executable is None:
        executable = shutil.which("ping")

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


def decode_output(output):
    return (output or b"").decode(locale.getpreferredencoding(False), errors="replace")


@app.get("/diagnostics/ping")
def diagnostics_ping():
    values = request.args.getlist("host")
    if len(values) != 1:
        return jsonify(error="Exactly one host parameter is required"), 400

    validated = validate_host(values[0])
    if validated is None:
        return jsonify(error="Invalid host parameter"), 400

    host, ip_version = validated

    try:
        command = build_ping_command(host, ip_version)
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            timeout=6,
            check=False,
        )
    except FileNotFoundError:
        return jsonify(error="Ping utility is unavailable"), 503
    except subprocess.TimeoutExpired as exc:
        output = decode_output(exc.stdout)
        if not output:
            output = "Ping operation timed out.\n"
        return Response(output, status=504, content_type="text/plain; charset=utf-8")
    except OSError:
        return jsonify(error="Unable to execute ping utility"), 500

    response = Response(
        decode_output(result.stdout),
        status=200 if result.returncode == 0 else 502,
        content_type="text/plain; charset=utf-8",
    )
    response.headers["X-Ping-Exit-Code"] = str(result.returncode)
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
