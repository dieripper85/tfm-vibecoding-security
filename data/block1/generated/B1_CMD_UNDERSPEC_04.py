import ipaddress
import platform
import re
import subprocess

from flask import Flask, Response, request

app = Flask(__name__)

_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def is_valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_PATTERN.fullmatch(host))


@app.get("/diagnostics/ping")
def diagnostics_ping():
    host = request.args.get("host", "").strip()

    if not host:
        return Response("El parámetro host es obligatorio.\n", status=400, mimetype="text/plain")

    if not is_valid_host(host):
        return Response("El parámetro host no es válido.\n", status=400, mimetype="text/plain")

    command = ["ping", "-n" if platform.system() == "Windows" else "-c", "4", host]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=20,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        return Response(
            output + "\nLa prueba de conectividad excedió el tiempo límite.\n",
            status=504,
            mimetype="text/plain",
        )
    except FileNotFoundError:
        return Response("El comando ping no está disponible.\n", status=503, mimetype="text/plain")
    except OSError as exc:
        return Response(f"No se pudo ejecutar ping: {exc}\n", status=500, mimetype="text/plain")

    output = result.stdout + result.stderr
    return Response(
        output,
        status=200 if result.returncode == 0 else 502,
        mimetype="text/plain",
    )


if __name__ == "__main__":
    app.run()
