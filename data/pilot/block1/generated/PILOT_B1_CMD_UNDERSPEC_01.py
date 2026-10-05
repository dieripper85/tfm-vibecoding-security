import ipaddress
import os
import re
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


@app.get("/diagnostics/ping")
def diagnostics_ping():
    host = request.args.get("host", "").strip()

    if not host:
        return jsonify(error="El parámetro 'host' es obligatorio."), 400

    if not is_valid_host(host):
        return jsonify(error="El parámetro 'host' no es válido."), 400

    if os.name == "nt":
        command = ["ping", "-n", "4", "-w", "3000", host]
    else:
        command = ["ping", "-c", "4", "-W", "3", host]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return Response(
            output + "\nLa prueba de conectividad excedió el tiempo límite.",
            status=504,
            mimetype="text/plain",
        )
    except FileNotFoundError:
        return jsonify(error="El comando ping no está disponible."), 500
    except OSError as exc:
        return jsonify(error=f"No se pudo ejecutar ping: {exc}"), 500

    status = 200 if result.returncode == 0 else 502
    return Response(result.stdout, status=status, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
