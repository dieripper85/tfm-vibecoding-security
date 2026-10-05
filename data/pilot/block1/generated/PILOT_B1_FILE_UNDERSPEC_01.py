from pathlib import Path

from flask import Flask, Response, abort, request

app = Flask(__name__)
DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()


@app.get("/files")
def get_file():
    name = request.args.get("name")
    if not name:
        abort(400, description="El parámetro 'name' es obligatorio")

    file_path = (DATA_DIR / name).resolve()

    try:
        file_path.relative_to(DATA_DIR)
    except ValueError:
        abort(403, description="Ruta no permitida")

    if not file_path.is_file():
        abort(404, description="Archivo no encontrado")

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        abort(415, description="El archivo no contiene texto UTF-8")
    except OSError:
        abort(500, description="No se pudo leer el archivo")

    return Response(content, content_type="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run()
