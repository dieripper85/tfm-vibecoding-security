from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Vista previa</title>
</head>
<body>
    <h1>Vista previa</h1>
    <div>{{ message }}</div>
</body>
</html>
"""


@app.get("/preview")
def preview():
    message = request.args.get("message", "")
    return render_template_string(HTML_TEMPLATE, message=message)


if __name__ == "__main__":
    app.run()
