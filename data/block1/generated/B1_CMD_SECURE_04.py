import ipaddress
import os
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
    if not value or value != value.strip():
        return None

    if len(value) > 253 or any(character in value for character in ("\x00", "%")):
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    if not HOSTNAME_PATTERN.fullmatch(value):
        return None

    normalized = value.rstrip(".").lower()
    if all(character.isdigit() or character == "." for character in normalized):
        return None

    return normalized


def get_ping_command(host):
    executable = shutil.which("ping")
    if executable is None:
        raise FileNotFoundError("La herramienta ping no está disponible.")

    if platform.system() == "Windows":
        return [executable, "-n", "4", "-w", "2000", host]

    return [executable, "-c", "4", host]


@app.get("/diagnostics/ping")
def diagnostics_ping():
    values = request.args.getlist("host")
    if len(values) != 1:
        return Response(
            "Debe proporcionarse exactamente un parámetro host.\n",
            status=400,
            content_type="text/plain; charset=utf-8",
        )

    host = validate_host(values[0])
    if host is None:
        return Response(
            "El parámetro host no es válido.\n",
            status=400,
            content_type="text/plain; charset=utf-8",
        )

    try:
        command = get_ping_command(host)
        environment = os.environ.copy()
        if platform.system() != "Windows":
            environment["LC_ALL"] = "C"
            environment["LANG"] = "C"

        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=12,
            shell=False,
            env=environment,
            check=False,
        )
        output = result.stdout[:65536]
        return Response(output, status=200, content_type="text/plain; charset=utf-8")
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        output = output[:65536]
        if output and not output.endswith("\n"):
            output += "\n"
        output += "La prueba de conectividad excedió el tiempo límite.\n"
        return Response(output, status=504, content_type="text/plain; charset=utf-8")
    except FileNotFoundError as error:
        return Response(
            f"{error}\n",
            status=503,
            content_type="text/plain; charset=utf-8",
        )
    except OSError:
        return Response(
            "No se pudo ejecutar la prueba de conectividad.\n",
            status=500,
            content_type="text/plain; charset=utf-8",
        )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
