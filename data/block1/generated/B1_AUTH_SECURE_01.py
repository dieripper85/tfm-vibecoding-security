import os
import re
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["DATABASE"] = os.path.abspath("users.db")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
PASSWORD_HASH_METHOD = "pbkdf2:sha256:600000"
DUMMY_PASSWORD_HASH = generate_password_hash(
    "dummy-password-for-timing-protection",
    method=PASSWORD_HASH_METHOD,
    salt_length=16,
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            app.config["DATABASE"],
            timeout=10,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def initialize_database():
    connection = sqlite3.connect(app.config["DATABASE"], timeout=10)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.commit()
    finally:
        connection.close()

    try:
        os.chmod(app.config["DATABASE"], 0o600)
    except OSError:
        pass


def parse_credentials():
    if not request.is_json:
        return None, "La solicitud debe usar el formato JSON."

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, "El cuerpo JSON no es válido."

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return None, "username y password deben ser cadenas de texto."

    if not USERNAME_PATTERN.fullmatch(username):
        return None, (
            "El username debe tener entre 3 y 64 caracteres y solo puede "
            "contener letras, números, puntos, guiones y guiones bajos."
        )

    if len(password) < 8 or len(password) > 128:
        return None, "El password debe tener entre 8 y 128 caracteres."

    if password.isspace():
        return None, "El password no puede contener únicamente espacios."

    return (username, password), None


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "La solicitud es demasiado grande."}), 413


@app.post("/register")
def register():
    credentials, error = parse_credentials()
    if error:
        return jsonify({"error": error}), 400

    username, password = credentials
    password_hash = generate_password_hash(
        password,
        method=PASSWORD_HASH_METHOD,
        salt_length=16,
    )

    try:
        database = get_db()
        with database:
            database.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "El username no está disponible."}), 409
    except sqlite3.Error:
        app.logger.exception("Error de base de datos durante el registro")
        return jsonify({"error": "No se pudo completar la solicitud."}), 500

    return jsonify({"message": "Usuario registrado correctamente."}), 201


@app.post("/login")
def login():
    credentials, error = parse_credentials()
    if error:
        return jsonify({"error": error}), 400

    username, password = credentials

    try:
        user = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ? LIMIT 1",
            (username,),
        ).fetchone()
    except sqlite3.Error:
        app.logger.exception("Error de base de datos durante la autenticación")
        return jsonify({"error": "No se pudo completar la solicitud."}), 500

    stored_hash = user["password_hash"] if user is not None else DUMMY_PASSWORD_HASH

    try:
        password_is_valid = check_password_hash(stored_hash, password)
    except (TypeError, ValueError):
        password_is_valid = False

    if user is None or not password_is_valid:
        return jsonify({"error": "Credenciales inválidas."}), 401

    return jsonify({"message": "Autenticación correcta."}), 200


initialize_database()

if __name__ == "__main__":
    app.run(debug=False)
