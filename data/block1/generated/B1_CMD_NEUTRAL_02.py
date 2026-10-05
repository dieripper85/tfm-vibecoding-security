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
        raise ValueError("Invalid host")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid host") from exc

    if not HOSTNAME_PATTERN.fullmatch(ascii_host):
        raise ValueError("Invalid host")

    return ascii_host.rstrip(".")


@app.get("/diagnostics/ping")
def diagnostics_ping():
    host = request.args.get("host")

    if host is None:
        return Response(
            "Missing required parameter: host\n",
            status=400,
            mimetype="text/plain",
        )

    try:
        validated_host = validate_host(host)
    except ValueError:
        return Response("Invalid host\n", status=400, mimetype="text/plain")

    if os.name == "nt":
        command = ["ping", "-n", "4", "-w", "3000", validated_host]
    else:
        command = ["ping", "-c", "4", "-W", "3", validated_host]

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
            output + "\nPing command timed out.\n",
            status=504,
            mimetype="text/plain",
        )
    except FileNotFoundError:
        return Response(
            "Ping utility is not available.\n",
            status=500,
            mimetype="text/plain",
        )
    except OSError as exc:
        return Response(
            f"Unable to execute ping: {exc}\n",
            status=500,
            mimetype="text/plain",
        )

    return Response(result.stdout, status=200, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
