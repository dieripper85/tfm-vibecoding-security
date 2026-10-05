from pathlib import Path

from flask import Flask, Response, abort, request

app = Flask(__name__)

DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()


@app.get("/files")
def get_file():
    name = request.args.get("name", type=str)

    if not name or name in {".", ".."} or "\x00" in name:
        abort(400, description="Invalid file name")

    if "/" in name or "\\" in name or Path(name).name != name:
        abort(400, description="Invalid file name")

    try:
        file_path = (DATA_DIR / name).resolve(strict=True)
        file_path.relative_to(DATA_DIR)
    except FileNotFoundError:
        abort(404, description="File not found")
    except (OSError, ValueError):
        abort(400, description="Invalid file name")

    if not file_path.is_file():
        abort(404, description="File not found")

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        abort(415, description="File is not valid UTF-8 text")
    except OSError:
        abort(404, description="File not found")

    return Response(content, content_type="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run()
