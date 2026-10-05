import os
import re
import sqlite3

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["JSON_SORT_KEYS"] = False

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
DUMMY_PASSWORD_HASH = generate_password_hash(
    "dummy-password-for-timing-protection",
    method="scrypt",
)


def get_connection():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with get_connection() as connection:
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
    try:
        os.chmod(DATABASE, 0o600)
    except OSError:
        pass


def parse_json_request():
    if not request.is_json:
        return None, (jsonify(error="El contenido debe ser JSON"), 415)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify(error="El cuerpo JSON debe ser un objeto"), 400)

    return data, None


def validate_credentials(data, registration=False):
    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return None, None, "username y password deben ser cadenas de texto"

    if username != username.strip():
        return None, None, "El username no puede contener espacios al inicio o al final"

    if not USERNAME_PATTERN.fullmatch(username):
        return None, None, (
            "El username debe tener entre 3 y 32 caracteres y solo puede contener "
            "letras, números, puntos, guiones y guiones bajos"
        )

    if len(password) > 128:
        return None, None, "El password no puede superar los 128 caracteres"

    if registration and len(password) < 12:
        return None, None, "El password debe tener al menos 12 caracteres"

    if not registration and not password:
        return None, None, "username y password son obligatorios"

    return username, password, None


@app.post("/register")
def register():
    data, error_response = parse_json_request()
    if error_response:
        return error_response

    username, password, validation_error = validate_credentials(
        data,
        registration=True,
    )
    if validation_error:
        return jsonify(error=validation_error), 400

    password_hash = generate_password_hash(password, method="scrypt")

    try:
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
    except sqlite3.IntegrityError:
        return jsonify(error="No se pudo registrar el usuario"), 409
    except sqlite3.Error:
        return jsonify(error="No se pudo completar la solicitud"), 500

    return jsonify(message="Usuario registrado correctamente"), 201


@app.post("/login")
def login():
    data, error_response = parse_json_request()
    if error_response:
        return error_response

    username, password, validation_error = validate_credentials(
        data,
        registration=False,
    )
    if validation_error:
        return jsonify(error=validation_error), 400

    try:
        with get_connection() as connection:
            user = connection.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
    except sqlite3.Error:
        return jsonify(error="No se pudo completar la solicitud"), 500

    stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH

    try:
        authenticated = check_password_hash(stored_hash, password)
    except (TypeError, ValueError):
        authenticated = False

    if not user or not authenticated:
        return jsonify(error="Credenciales inválidas"), 401

    return jsonify(message="Autenticación exitosa"), 200


@app.errorhandler(HTTPException)
def handle_http_error(error):
    messages = {
        404: "Recurso no encontrado",
        405: "Método no permitido",
        413: "La solicitud es demasiado grande",
        415: "Tipo de contenido no compatible",
    }
    return jsonify(error=messages.get(error.code, "Solicitud inválida")), error.code


@app.errorhandler(Exception)
def handle_unexpected_error(_error):
    return jsonify(error="Error interno del servidor"), 500


initialize_database()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
