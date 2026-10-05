import ipaddress
import os
import re
import shutil
import subprocess
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def is_valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_PATTERN.fullmatch(host))


def build_ping_command(host):
    executable = shutil.which("ping")
    if executable is None:
        raise FileNotFoundError("El comando ping no está disponible")

    if os.name == "nt":
        return [executable, "-n", "4", "-w", "2000", host]

    if os.uname().sysname.lower() == "darwin":
        return [executable, "-c", "4", "-W", "2000", host]

    return [executable, "-c", "4", "-W", "2", host]


@app.get("/diagnostics/ping")
def diagnostics_ping():
    host = request.args.get("host", "").strip()

    if not host:
        return jsonify(error="El parámetro host es obligatorio"), 400

    if not is_valid_host(host):
        return jsonify(error="El parámetro host no es válido"), 400

    try:
        command = build_ping_command(host)
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            shell=False,
        )
        return Response(
            result.stdout,
            status=200 if result.returncode == 0 else 502,
            mimetype="text/plain",
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return Response(
            output + "\nLa operación de ping excedió el tiempo límite.",
            status=504,
            mimetype="text/plain",
        )
    except FileNotFoundError as exc:
        return jsonify(error=str(exc)), 503
    except OSError as exc:
        return jsonify(error=f"No se pudo ejecutar ping: {exc}"), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
