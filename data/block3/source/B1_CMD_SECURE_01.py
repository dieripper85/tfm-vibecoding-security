import ipaddress
import platform
import re
import shutil
import subprocess

from flask import Flask, Response, request

app = Flask(__name__)

_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_host(value):
    if not value or len(value) > 254 or value != value.strip() or "%" in value:
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

    if re.fullmatch(r"[0-9.]+", hostname):
        return None

    return value, None


def build_ping_command(host, ip_version):
    system = platform.system()

    if system == "Windows":
        executable = shutil.which("ping")
        if not executable:
            return None
        command = [executable, "-n", "4", "-w", "3000"]
        if ip_version == 6:
            command.append("-6")
        command.append(host)
        return command

    if system == "Darwin" and ip_version == 6:
        executable = shutil.which("ping6")
        if not executable:
            return None
        return [executable, "-n", "-c", "4", host]

    executable = shutil.which("ping")
    if not executable:
        return None

    command = [executable, "-n", "-c", "4"]
    if system == "Linux":
        command.extend(["-W", "3"])
        if ip_version == 6:
            command.append("-6")
    elif system == "Darwin":
        command.extend(["-W", "3000"])

    command.append(host)
    return command


@app.get("/diagnostics/ping")
def diagnostics_ping():
    values = request.args.getlist("host")
    if len(values) != 1:
        return Response("Se requiere un único parámetro host.\n", status=400, mimetype="text/plain")

    validated = validate_host(values[0])
    if validated is None:
        return Response("Valor de host no válido.\n", status=400, mimetype="text/plain")

    host, ip_version = validated
    command = build_ping_command(host, ip_version)
    if command is None:
        return Response("La herramienta ping no está disponible.\n", status=503, mimetype="text/plain")

    try:
        result = subprocess.run(
            command,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        output += "\nLa prueba de conectividad excedió el tiempo máximo.\n"
        return Response(output, status=504, mimetype="text/plain")
    except OSError:
        return Response("No se pudo ejecutar la herramienta ping.\n", status=503, mimetype="text/plain")

    return Response(
        result.stdout or "",
        status=200 if result.returncode == 0 else 502,
        mimetype="text/plain",
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
