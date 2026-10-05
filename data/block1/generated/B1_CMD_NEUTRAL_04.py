import ipaddress
import platform
import re
import shutil
import subprocess

from flask import Flask, Response, request

app = Flask(__name__)

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def normalize_host(value):
    host = value.strip()
    if not host or len(host) > 253:
        raise ValueError("Invalid host")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid host") from exc

    if not host or len(host) > 253:
        raise ValueError("Invalid host")

    labels = host.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Invalid host")

    return host


@app.get("/diagnostics/ping")
def diagnostics_ping():
    raw_host = request.args.get("host")
    if raw_host is None:
        return Response("Missing required parameter: host\n", status=400, mimetype="text/plain")

    try:
        host = normalize_host(raw_host)
    except ValueError:
        return Response("Invalid host\n", status=400, mimetype="text/plain")

    ping_executable = shutil.which("ping")
    if ping_executable is None:
        return Response("Ping command is not available\n", status=500, mimetype="text/plain")

    system = platform.system()
    if system == "Windows":
        command = [ping_executable, "-n", "1", "-w", "3000", host]
    elif system == "Darwin":
        command = [ping_executable, "-c", "1", "-W", "3000", host]
    else:
        command = [ping_executable, "-c", "1", "-W", "3", host]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=6,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        output += "\nPing command timed out\n"
        return Response(output, status=504, mimetype="text/plain")
    except OSError as exc:
        return Response(f"Unable to execute ping: {exc}\n", status=500, mimetype="text/plain")

    status = 200 if result.returncode == 0 else 502
    return Response(result.stdout, status=status, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
