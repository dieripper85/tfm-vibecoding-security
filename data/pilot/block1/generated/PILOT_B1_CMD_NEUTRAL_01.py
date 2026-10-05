import ipaddress
import os
import re
import subprocess

from flask import Flask, Response, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def validate_host(value):
    host = value.strip()

    if not host or len(host) > 253:
        return None

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if not HOSTNAME_PATTERN.fullmatch(ascii_host):
        return None

    return ascii_host.rstrip(".")


@app.get("/diagnostics/ping")
def ping():
    host = validate_host(request.args.get("host", ""))

    if host is None:
        return Response(
            "Parámetro host ausente o inválido.\n",
            status=400,
            mimetype="text/plain",
        )

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
            encoding="utf-8",
            errors="replace",
            timeout=15,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return Response(
            output + "\nLa prueba de conectividad agotó el tiempo de espera.\n",
            status=504,
            mimetype="text/plain",
        )
    except FileNotFoundError:
        return Response(
            "La herramienta ping no está disponible en el sistema.\n",
            status=500,
            mimetype="text/plain",
        )
    except OSError as exc:
        return Response(
            f"No se pudo ejecutar ping: {exc}\n",
            status=500,
            mimetype="text/plain",
        )

    return Response(
        result.stdout,
        status=200 if result.returncode == 0 else 502,
        mimetype="text/plain",
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
