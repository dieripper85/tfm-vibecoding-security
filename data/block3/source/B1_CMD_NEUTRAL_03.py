import ipaddress
import platform
import re
import shutil
import subprocess

from flask import Flask, Response, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def validate_host(value):
    if not value or len(value) > 253:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if not HOSTNAME_PATTERN.fullmatch(ascii_host):
        return None

    return ascii_host.rstrip(".")


@app.get("/diagnostics/ping")
def ping():
    host = validate_host(request.args.get("host", "").strip())
    if host is None:
        return Response("Parámetro host inválido.\n", status=400, mimetype="text/plain")

    ping_executable = shutil.which("ping")
    if ping_executable is None:
        return Response(
            "La herramienta ping no está disponible.\n",
            status=503,
            mimetype="text/plain",
        )

    system = platform.system()
    if system == "Windows":
        command = [ping_executable, "-n", "4", "-w", "3000", host]
    elif system == "Darwin":
        command = [ping_executable, "-c", "4", "-W", "3000", host]
    else:
        command = [ping_executable, "-c", "4", "-W", "3", "--", host]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=15,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        output += "\nLa operación de ping excedió el tiempo límite.\n"
        return Response(output, status=504, mimetype="text/plain")
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
