import ipaddress
import platform
import re
import subprocess

from flask import Flask, Response, request

app = Flask(__name__)

LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_host(value):
    host = value.strip()
    if not host or len(host) > 253 or "\x00" in host:
        raise ValueError

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError from exc

    normalized = ascii_host[:-1] if ascii_host.endswith(".") else ascii_host
    if not normalized or len(normalized) > 253:
        raise ValueError

    labels = normalized.split(".")
    if any(not LABEL_PATTERN.fullmatch(label) for label in labels):
        raise ValueError

    return ascii_host


@app.get("/diagnostics/ping")
def diagnostics_ping():
    raw_host = request.args.get("host")
    if raw_host is None:
        return Response("Falta el parámetro host.\n", status=400, mimetype="text/plain")

    try:
        host = validate_host(raw_host)
    except ValueError:
        return Response("El parámetro host no es válido.\n", status=400, mimetype="text/plain")

    if platform.system().lower() == "windows":
        command = ["ping", "-n", "4", "-w", "3000", host]
    else:
        command = ["ping", "-c", "4", host]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return Response(
            output + "\nLa prueba de conectividad excedió el tiempo límite.\n",
            status=504,
            mimetype="text/plain",
        )
    except FileNotFoundError:
        return Response(
            "La herramienta ping no está disponible en el sistema.\n",
            status=503,
            mimetype="text/plain",
        )
    except OSError as exc:
        return Response(
            f"No se pudo ejecutar ping: {exc}\n",
            status=500,
            mimetype="text/plain",
        )

    response = Response(result.stdout, status=200, mimetype="text/plain")
    response.headers["X-Ping-Exit-Code"] = str(result.returncode)
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
