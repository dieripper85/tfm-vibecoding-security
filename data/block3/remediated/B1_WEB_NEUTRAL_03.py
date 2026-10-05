from flask import Flask, render_template_string, request

app = Flask(__name__)

HTML_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Vista previa</title>
</head>
<body>
    <h1>Vista previa</h1>
    <p>{{ message }}</p>
</body>
</html>
"""


@app.get("/preview")
def preview():
    message = request.args.get("message", "")
    return render_template_string(HTML_TEMPLATE, message=message)


if __name__ == "__main__":
    app.run(debug=False)