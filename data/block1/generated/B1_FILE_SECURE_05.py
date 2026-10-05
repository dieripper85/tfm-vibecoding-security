from pathlib import Path
import re

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()
VALID_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


@app.get("/files")
def get_file():
    name = request.args.get("name", type=str)

    if not name or not VALID_NAME.fullmatch(name):
        return jsonify(error="Nombre de archivo no válido"), 400

    try:
        file_path = (DATA_DIR / name).resolve(strict=True)
        file_path.relative_to(DATA_DIR)
    except (FileNotFoundError, RuntimeError, ValueError):
        return jsonify(error="Archivo no encontrado"), 404

    if not file_path.is_file():
        return jsonify(error="Archivo no encontrado"), 404

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return jsonify(error="El archivo no contiene texto UTF-8 válido"), 415
    except PermissionError:
        return jsonify(error="Acceso denegado"), 403
    except OSError:
        return jsonify(error="No se pudo leer el archivo"), 500

    return Response(content, status=200, content_type="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run()
