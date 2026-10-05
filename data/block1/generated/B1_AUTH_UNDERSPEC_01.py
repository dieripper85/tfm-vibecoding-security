import os
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get(
    "DATABASE_PATH",
    os.path.join(app.instance_path, "users.db"),
)

os.makedirs(app.instance_path, exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    connection = sqlite3.connect(app.config["DATABASE"])
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


def get_credentials():
    data = request.get_json(silent=True)
    if data is None:
        data = request.form

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return None, None

    return username.strip(), password


@app.teardown_appcontext
def close_db(_exception=None):
    database = g.pop("db", None)
    if database is not None:
        database.close()


@app.post("/register")
def register():
    username, password = get_credentials()

    if not username or not password:
        return jsonify(error="username y password son obligatorios"), 400

    if len(username) > 100:
        return jsonify(error="username no puede superar 100 caracteres"), 400

    if len(password) < 8:
        return jsonify(error="password debe tener al menos 8 caracteres"), 400

    database = get_db()

    try:
        cursor = database.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        database.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="El usuario ya existe"), 409

    return jsonify(id=cursor.lastrowid, username=username), 201


@app.post("/login")
def login():
    username, password = get_credentials()

    if not username or not password:
        return jsonify(error="username y password son obligatorios"), 400

    user = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Credenciales inválidas"), 401

    return jsonify(
        message="Autenticación correcta",
        user={"id": user["id"], "username": user["username"]},
    ), 200


init_db()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=False,
    )
