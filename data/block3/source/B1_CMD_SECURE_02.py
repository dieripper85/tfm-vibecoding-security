import ipaddress
import os
import re
import shutil
import subprocess

from flask import Flask, Response, request

app = Flask(__name__)

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_host(value):
    if not value or len(value) > 253 or not value.isascii():
        return None

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if ":" in value or re.fullmatch(r"[0-9.]+", value):
        return None

    normalized = value[:-1] if value.endswith(".") else value
    if not normalized or len(normalized) > 253:
        return None

    labels = normalized.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        return None

    return value


@app.get("/diagnostics/ping")
def diagnostics_ping():
    values = request.args.getlist("host")
    if len(values) != 1:
        return Response("Se requiere un único parámetro host.\n", status=400, mimetype="text/plain")

    host = validate_host(values[0])
    if host is None:
        return Response("Valor de host no válido.\n", status=400, mimetype="text/plain")

    ping_executable = shutil.which("ping")
    if ping_executable is None:
        return Response("La herramienta ping no está disponible.\n", status=503, mimetype="text/plain")

    if os.name == "nt":
        command = [ping_executable, "-n", "1", "-w", "3000", host]
    else:
        command = [ping_executable, "-c", "1", host]

    try:
        result = subprocess.run(
            command,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        return Response(result.stdout, status=200, mimetype="text/plain")
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return Response(f"{output}\nLa prueba de conectividad excedió el tiempo límite.\n", status=504, mimetype="text/plain")
    except OSError:
        return Response("No se pudo ejecutar la herramienta ping.\n", status=500, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
