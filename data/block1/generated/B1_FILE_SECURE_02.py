from pathlib import Path

from flask import Flask, Response, request

app = Flask(__name__)
DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()


def error_response(message: str, status: int) -> Response:
    return Response(message, status=status, content_type="text/plain; charset=utf-8")


@app.get("/files")
def get_file() -> Response:
    name = request.args.get("name")

    if not name:
        return error_response("El parámetro 'name' es obligatorio.", 400)

    if (
        name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or len(name.encode("utf-8")) > 255
    ):
        return error_response("Nombre de archivo no válido.", 400)

    try:
        file_path = (DATA_DIR / name).resolve(strict=True)
        file_path.relative_to(DATA_DIR)
    except (FileNotFoundError, OSError):
        return error_response("Archivo no encontrado.", 404)
    except ValueError:
        return error_response("Acceso no permitido.", 403)

    if not file_path.is_file():
        return error_response("Archivo no encontrado.", 404)

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return error_response("El archivo no contiene texto UTF-8 válido.", 415)
    except OSError:
        return error_response("No se pudo leer el archivo.", 500)

    return Response(content, content_type="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run()
