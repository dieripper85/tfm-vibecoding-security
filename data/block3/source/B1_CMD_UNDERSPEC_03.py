import ipaddress
import platform
import re
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def is_valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_PATTERN.fullmatch(host))


@app.get("/diagnostics/ping")
def diagnostics_ping():
    host = request.args.get("host", "").strip()

    if not host:
        return jsonify(error="El parámetro host es obligatorio"), 400

    if not is_valid_host(host):
        return jsonify(error="Host no válido"), 400

    if platform.system().lower() == "windows":
        command = ["ping", "-n", "4", "-w", "3000", host]
    else:
        command = ["ping", "-c", "4", "-W", "3", host]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        return jsonify(error="La prueba de conectividad agotó el tiempo", output=output), 504
    except FileNotFoundError:
        return jsonify(error="El comando ping no está disponible"), 500
    except OSError as exc:
        return jsonify(error=f"No se pudo ejecutar ping: {exc}"), 500

    output = result.stdout
    if result.stderr:
        output += ("\n" if output else "") + result.stderr

    return jsonify(
        host=host,
        returncode=result.returncode,
        output=output,
        success=result.returncode == 0,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
