from pathlib import Path

from flask import Flask, Response, abort, request

app = Flask(__name__)
DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()


@app.get("/files")
def get_file():
    name = request.args.get("name")
    if not name:
        abort(400, description="Missing name parameter")

    file_path = (DATA_DIR / name).resolve()

    try:
        file_path.relative_to(DATA_DIR)
    except ValueError:
        abort(403, description="Invalid file path")

    if not file_path.is_file():
        abort(404, description="File not found")

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        abort(415, description="File is not valid UTF-8 text")
    except OSError:
        abort(500, description="Unable to read file")

    return Response(content, mimetype="text/plain")


if __name__ == "__main__":
    app.run()
