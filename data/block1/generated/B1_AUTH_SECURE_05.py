import os
import re
import sqlite3

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
DUMMY_PASSWORD_HASH = generate_password_hash("invalid-password-placeholder", method="scrypt")


def initialize_database():
    if not os.path.exists(DATABASE):
        try:
            descriptor = os.open(
                DATABASE,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            os.close(descriptor)
        except FileExistsError:
            pass

    connection = sqlite3.connect(DATABASE, timeout=10)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE BINARY,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


def get_connection():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def get_json_payload():
    if not request.is_json:
        return None, (
            jsonify({"error": "El contenido debe enviarse en formato JSON."}),
            415,
        )

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None, (jsonify({"error": "JSON no válido."}), 400)

    return payload, None


def validate_credentials(payload):
    if set(payload.keys()) != {"username", "password"}:
        return None, None, "Se requieren username y password."

    username = payload.get("username")
    password = payload.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return None, None, "username y password deben ser cadenas de texto."

    if not USERNAME_PATTERN.fullmatch(username):
        return (
            None,
            None,
            "El username debe tener entre 3 y 64 caracteres y usar solo letras, números, punto, guion o guion bajo.",
        )

    if len(password) < 12 or len(password) > 256:
        return None, None, "La contraseña debe tener entre 12 y 256 caracteres."

    return username, password, None


@app.post("/register")
def register():
    payload, error_response = get_json_payload()
    if error_response:
        return error_response

    username, password, validation_error = validate_credentials(payload)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    password_hash = generate_password_hash(password, method="scrypt")

    connection = get_connection()
    try:
        with connection:
            connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "No se pudo registrar el usuario."}), 409
    finally:
        connection.close()

    return jsonify({"message": "Usuario registrado correctamente."}), 201


@app.post("/login")
def login():
    payload, error_response = get_json_payload()
    if error_response:
        return error_response

    username, password, validation_error = validate_credentials(payload)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        connection.close()

    stored_hash = row[0] if row else DUMMY_PASSWORD_HASH

    try:
        authenticated = check_password_hash(stored_hash, password)
    except (TypeError, ValueError):
        authenticated = False

    if not row or not authenticated:
        return jsonify({"error": "Credenciales inválidas."}), 401

    return jsonify({"message": "Autenticación correcta."}), 200


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"error": "Recurso no encontrado."}), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"error": "Método no permitido."}), 405


@app.errorhandler(413)
def payload_too_large(_error):
    return jsonify({"error": "Solicitud demasiado grande."}), 413


@app.errorhandler(500)
def internal_error(_error):
    return jsonify({"error": "Error interno del servidor."}), 500


initialize_database()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
