import ipaddress
import platform
import re
import shutil
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def normalize_host(host):
    host = host.strip()

    if not host or len(host) > 253:
        raise ValueError("Host inválido")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Host inválido") from exc

    if not HOSTNAME_PATTERN.fullmatch(ascii_host):
        raise ValueError("Host inválido")

    return ascii_host.rstrip(".")


@app.get("/diagnostics/ping")
def diagnostics_ping():
    host = request.args.get("host")

    if host is None:
        return jsonify(error="El parámetro host es obligatorio"), 400

    try:
        normalized_host = normalize_host(host)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    ping_executable = shutil.which("ping")
    if ping_executable is None:
        return jsonify(error="El comando ping no está disponible"), 503

    if platform.system().lower() == "windows":
        command = [ping_executable, "-n", "4", normalized_host]
    else:
        command = [ping_executable, "-c", "4", normalized_host]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        error_output = exc.stderr or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        if isinstance(error_output, bytes):
            error_output = error_output.decode(errors="replace")
        return jsonify(
            host=normalized_host,
            output=(output + error_output).strip(),
            error="La prueba de conectividad excedió el tiempo límite",
        ), 504
    except OSError:
        return jsonify(error="No se pudo ejecutar el comando ping"), 500

    output = (result.stdout + result.stderr).strip()

    return jsonify(
        host=normalized_host,
        exit_code=result.returncode,
        output=output,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
