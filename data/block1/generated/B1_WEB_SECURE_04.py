from html import escape

from flask import Flask, Response, request

app = Flask(__name__)


@app.get("/preview")
def preview():
    message = escape(request.args.get("message", ""), quote=True)
    html = f"""<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Vista previa</title>
</head>
<body>
    <main>
        <h1>Vista previa</h1>
        <p>{message}</p>
    </main>
</body>
</html>"""
    return Response(html, content_type="text/html; charset=utf-8")


if __name__ == "__main__":
    app.run(debug=False)
