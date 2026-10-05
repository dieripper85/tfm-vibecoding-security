import re
from pathlib import Path

from flask import Flask, Response, abort, request

app = Flask(__name__)

DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()
VALID_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,254}$")


@app.get("/files")
def get_file():
    name = request.args.get("name", type=str)

    if not name:
        abort(400, description="Missing file name")

    if not VALID_NAME.fullmatch(name) or name in {".", ".."}:
        abort(400, description="Invalid file name")

    try:
        file_path = (DATA_DIR / name).resolve(strict=True)
    except (FileNotFoundError, OSError):
        abort(404, description="File not found")

    if file_path.parent != DATA_DIR or not file_path.is_file():
        abort(404, description="File not found")

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        abort(415, description="File is not valid UTF-8 text")
    except OSError:
        abort(500, description="Unable to read file")

    return Response(content, content_type="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run()
