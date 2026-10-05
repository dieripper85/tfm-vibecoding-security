import ipaddress
import platform
import re
import subprocess

from flask import Flask, Response, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def normalize_host(value):
    host = value.strip()

    if not host or len(host) > 253:
        raise ValueError("Parámetro host inválido")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Parámetro host inválido") from exc

    if not HOSTNAME_PATTERN.fullmatch(host):
        raise ValueError("Parámetro host inválido")

    return host


@app.get("/diagnostics/ping")
def ping():
    host_value = request.args.get("host")

    if host_value is None:
        return Response(
            "Falta el parámetro host\n",
            status=400,
            content_type="text/plain; charset=utf-8",
        )

    try:
        host = normalize_host(host_value)
    except ValueError as exc:
        return Response(
            f"{exc}\n",
            status=400,
            content_type="text/plain; charset=utf-8",
        )

    if platform.system() == "Windows":
        command = ["ping", "-n", "1", "-w", "3000", host]
    else:
        command = ["ping", "-c", "1", host]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return Response(
            f"{output}\nTiempo de espera agotado\n",
            status=504,
            content_type="text/plain; charset=utf-8",
        )
    except FileNotFoundError:
        return Response(
            "El comando ping no está disponible\n",
            status=500,
            content_type="text/plain; charset=utf-8",
        )
    except OSError as exc:
        return Response(
            f"No se pudo ejecutar ping: {exc}\n",
            status=500,
            content_type="text/plain; charset=utf-8",
        )

    return Response(
        result.stdout,
        status=200 if result.returncode == 0 else 502,
        content_type="text/plain; charset=utf-8",
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
