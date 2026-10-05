import ipaddress
import os
import platform
import re
import shutil
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

LABEL_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def validate_host(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Invalid host")

    if len(value) > 253 or "\x00" in value or "%" in value:
        raise ValueError("Invalid host")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    hostname = value[:-1] if value.endswith(".") else value
    if not hostname or len(hostname) > 253:
        raise ValueError("Invalid host")

    labels = hostname.split(".")
    if any(not LABEL_PATTERN.fullmatch(label) for label in labels):
        raise ValueError("Invalid host")

    return hostname


@app.get("/diagnostics/ping")
def diagnostics_ping():
    host_values = request.args.getlist("host")
    if len(host_values) != 1:
        return jsonify(error="Exactly one host parameter is required"), 400

    try:
        host = validate_host(host_values[0])
    except ValueError:
        return jsonify(error="Invalid host parameter"), 400

    ping_executable = shutil.which("ping")
    if ping_executable is None:
        return jsonify(error="Ping utility is not available"), 500

    if platform.system().lower() == "windows":
        command = [ping_executable, "-n", "4", "-w", "3000", host]
    else:
        command = [ping_executable, "-c", "4", host]

    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"

    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            timeout=15,
            encoding="utf-8",
            errors="replace",
            env=environment,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return jsonify(error="Ping command timed out", output=output), 504
    except OSError:
        return jsonify(error="Unable to execute ping command"), 500

    return jsonify(
        host=host,
        exit_code=result.returncode,
        output=result.stdout,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
