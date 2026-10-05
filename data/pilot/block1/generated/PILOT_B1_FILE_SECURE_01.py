from pathlib import Path

from flask import Flask, Response, abort, request

app = Flask(__name__)

DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()


@app.get("/files")
def get_file():
    name = request.args.get("name", type=str)

    if (
        not name
        or len(name) > 255
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
    ):
        abort(400, description="Invalid file name")

    requested_path = (DATA_DIR / name).resolve()

    try:
        requested_path.relative_to(DATA_DIR)
    except ValueError:
        abort(403, description="Access denied")

    if not requested_path.is_file():
        abort(404, description="File not found")

    try:
        content = requested_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        abort(422, description="File is not valid UTF-8 text")
    except PermissionError:
        abort(403, description="Access denied")
    except OSError:
        abort(500, description="Unable to read file")

    return Response(content, mimetype="text/plain")


if __name__ == "__main__":
    app.run()
