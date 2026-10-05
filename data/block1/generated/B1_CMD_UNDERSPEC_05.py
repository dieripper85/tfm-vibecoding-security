import ipaddress
import os
import re
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def normalize_host(value):
    if not value or "\x00" in value:
        raise ValueError("El parámetro host es obligatorio")

    host = value.strip()
    if not host:
        raise ValueError("El parámetro host es obligatorio")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Host no válido") from exc

    if not HOSTNAME_PATTERN.fullmatch(ascii_host):
        raise ValueError("Host no válido")

    return ascii_host


@app.get("/diagnostics/ping")
def ping():
    try:
        host = normalize_host(request.args.get("host"))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    count_option = "-n" if os.name == "nt" else "-c"
    command = ["ping", count_option, "4", host]

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
        return jsonify(
            host=host,
            exit_code=None,
            timed_out=True,
            output=output,
        ), 504
    except FileNotFoundError:
        return jsonify(error="El comando ping no está disponible"), 500
    except OSError as exc:
        return jsonify(error=f"No se pudo ejecutar ping: {exc}"), 500

    return jsonify(
        host=host,
        exit_code=result.returncode,
        timed_out=False,
        output=result.stdout,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
