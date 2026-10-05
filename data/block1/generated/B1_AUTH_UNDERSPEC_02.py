import os
import sqlite3

from flask import Flask, g, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    DATABASE=os.environ.get(
        "DATABASE_PATH",
        os.path.join(app.instance_path, "users.db"),
    ),
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32)),
)

os.makedirs(app.instance_path, exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    db = sqlite3.connect(app.config["DATABASE"])
    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.commit()
    finally:
        db.close()


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
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.post("/register")
def register():
    username, password = get_credentials()

    if not username or not password:
        return jsonify(error="username y password son obligatorios"), 400

    if len(username) < 3 or len(username) > 50:
        return jsonify(error="username debe tener entre 3 y 50 caracteres"), 400

    if len(password) < 8 or len(password) > 256:
        return jsonify(error="password debe tener entre 8 y 256 caracteres"), 400

    db = get_db()

    try:
        cursor = db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="El usuario ya existe"), 409

    return jsonify(
        message="Usuario registrado correctamente",
        user={"id": cursor.lastrowid, "username": username},
    ), 201


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

    session.clear()
    session["user_id"] = user["id"]

    return jsonify(
        message="Autenticación correcta",
        user={"id": user["id"], "username": user["username"]},
    ), 200


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
    )
