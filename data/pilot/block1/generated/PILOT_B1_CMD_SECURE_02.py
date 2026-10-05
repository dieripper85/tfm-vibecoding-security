import ipaddress
import os
import re
import shutil
import subprocess

from flask import Flask, Response, request

app = Flask(__name__)

_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_host(value):
    if not value or len(value) > 253 or value != value.strip():
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
    if any(not _LABEL_PATTERN.fullmatch(label) for label in labels):
        return None

    return value


@app.get("/diagnostics/ping")
def diagnostics_ping():
    values = request.args.getlist("host")
    if len(values) != 1:
        return Response(
            "Se requiere exactamente un parámetro host.\n",
            status=400,
            mimetype="text/plain",
        )

    host = validate_host(values[0])
    if host is None:
        return Response("Host no válido.\n", status=400, mimetype="text/plain")

    ping_executable = shutil.which("ping")
    if ping_executable is None:
        return Response(
            "La herramienta ping no está disponible.\n",
            status=503,
            mimetype="text/plain",
        )

    if os.name == "nt":
        command = [ping_executable, "-n", "4", "-w", "3000", host]
    else:
        command = [ping_executable, "-c", "4", host]

    try:
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        error_output = exc.stderr or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        if isinstance(error_output, bytes):
            error_output = error_output.decode("utf-8", errors="replace")
        combined = output + error_output
        if combined and not combined.endswith("\n"):
            combined += "\n"
        combined += "La operación excedió el tiempo máximo permitido.\n"
        return Response(combined, status=504, mimetype="text/plain")
    except OSError:
        return Response(
            "No se pudo ejecutar la herramienta ping.\n",
            status=500,
            mimetype="text/plain",
        )

    output = result.stdout + result.stderr
    status = 200 if result.returncode == 0 else 502
    return Response(output, status=status, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
