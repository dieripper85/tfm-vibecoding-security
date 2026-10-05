import os
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get(
    "DATABASE_PATH",
    os.path.join(app.instance_path, "users.db"),
)


def get_db():
    if "db" not in g:
        database_path = app.config["DATABASE"]
        os.makedirs(os.path.dirname(os.path.abspath(database_path)), exist_ok=True)
        g.db = sqlite3.connect(database_path, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    database = get_db()
    database.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    database.commit()


@app.teardown_appcontext
def close_db(_error=None):
    database = g.pop("db", None)
    if database is not None:
        database.close()


def get_credentials():
    data = request.get_json(silent=True) if request.is_json else request.form

    if not data:
        return None, None

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return None, None

    return username.strip(), password


@app.post("/register")
def register():
    username, password = get_credentials()

    if not username or not password:
        return jsonify(error="username y password son obligatorios"), 400

    if len(username) > 80:
        return jsonify(error="El username no puede superar 80 caracteres"), 400

    if len(password) > 1024:
        return jsonify(error="La contraseña es demasiado larga"), 400

    database = get_db()

    try:
        cursor = database.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        database.commit()
    except sqlite3.IntegrityError:
        database.rollback()
        return jsonify(error="El username ya está registrado"), 409

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
        message="Autenticación exitosa",
        user={"id": user["id"], "username": user["username"]},
    ), 200


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=False,
    )
