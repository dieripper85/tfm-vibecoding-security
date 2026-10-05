from pathlib import Path

from flask import Flask, Response, request

app = Flask(__name__)

DATA_DIR = (Path(__file__).resolve().parent / "data").resolve()


@app.get("/files")
def get_file():
    name = request.args.get("name", type=str)

    if not name:
        return Response("Missing name parameter", status=400, mimetype="text/plain")

    file_path = (DATA_DIR / name).resolve()

    if DATA_DIR not in file_path.parents or not file_path.is_file():
        return Response("File not found", status=404, mimetype="text/plain")

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return Response("File is not valid UTF-8 text", status=415, mimetype="text/plain")
    except OSError:
        return Response("Unable to read file", status=500, mimetype="text/plain")

    return Response(content, status=200, content_type="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run()
