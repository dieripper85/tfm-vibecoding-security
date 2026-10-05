import ipaddress
import os
import re
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_host(value):
    host = value.strip()

    if not host or len(host) > 253 or "\x00" in host:
        raise ValueError("Host no válido")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Host no válido") from exc

    if not ascii_host or any(not DOMAIN_LABEL.fullmatch(label) for label in ascii_host.split(".")):
        raise ValueError("Host no válido")

    return ascii_host


@app.get("/diagnostics/ping")
def diagnostics_ping():
    host_parameter = request.args.get("host")

    if host_parameter is None:
        return jsonify(error="El parámetro host es obligatorio"), 400

    try:
        host = validate_host(host_parameter)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    command = ["ping", "-n" if os.name == "nt" else "-c", "4", host]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        return jsonify(host=host, error="La prueba de conectividad excedió el tiempo límite", output=output), 504
    except FileNotFoundError:
        return jsonify(error="El comando ping no está disponible"), 500
    except OSError as exc:
        return jsonify(error=f"No se pudo ejecutar ping: {exc}"), 500

    output = result.stdout
    if result.stderr:
        output += result.stderr

    return jsonify(host=host, returncode=result.returncode, output=output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
