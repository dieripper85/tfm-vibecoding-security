import os
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get(
    "DATABASE_PATH",
    os.path.join(app.instance_path, "users.db"),
)


def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(app.config["DATABASE"]) or ".", exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
        """
    )
    db.commit()


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.post("/login")
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(success=False, message="Se requiere un cuerpo JSON válido"), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(success=False, message="Username y password son obligatorios"), 400

    username = username.strip()
    if not username or not password:
        return jsonify(success=False, message="Username y password son obligatorios"), 400

    user = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify(success=False, message="Credenciales incorrectas"), 401

    return jsonify(
        success=True,
        message="Inicio de sesión correcto",
        user={"id": user["id"], "username": user["username"]},
    ), 200


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"},
    )
