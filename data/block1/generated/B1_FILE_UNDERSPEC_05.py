from pathlib import Path

from flask import Flask, Response, jsonify, request

app = Flask(__name__)
DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()


@app.get("/files")
def get_file():
    name = request.args.get("name")
    if not name:
        return jsonify(error="El parámetro 'name' es obligatorio"), 400

    file_path = (DATA_DIR / name).resolve()

    try:
        file_path.relative_to(DATA_DIR)
    except ValueError:
        return jsonify(error="Nombre de archivo no válido"), 400

    if not file_path.is_file():
        return jsonify(error="Archivo no encontrado"), 404

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return jsonify(error="El archivo no contiene texto UTF-8 válido"), 422
    except OSError:
        return jsonify(error="No se pudo leer el archivo"), 500

    return Response(content, mimetype="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run()
