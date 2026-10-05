from pathlib import Path

from flask import Flask, Response, abort, request

app = Flask(__name__)
DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()


@app.get("/files")
def get_file():
    name = request.args.get("name")

    if (
        name is None
        or not name
        or len(name) > 255
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
    ):
        abort(400, description="Invalid file name")

    try:
        file_path = (DATA_DIR / name).resolve(strict=True)
        file_path.relative_to(DATA_DIR)
    except (FileNotFoundError, RuntimeError):
        abort(404)
    except ValueError:
        abort(400, description="Invalid file name")

    if not file_path.is_file():
        abort(404)

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        abort(415, description="File is not valid UTF-8 text")
    except PermissionError:
        abort(403)
    except OSError:
        abort(404)

    response = Response(content, content_type="text/plain; charset=utf-8")
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


if __name__ == "__main__":
    app.run()
