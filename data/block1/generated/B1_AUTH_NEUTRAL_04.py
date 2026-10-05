import sqlite3

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
DATABASE = "users.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        connection.commit()


@app.post("/register")
def register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Se requiere un cuerpo JSON válido"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not username.strip():
        return jsonify({"error": "El username es obligatorio"}), 400

    if not isinstance(password, str) or not password:
        return jsonify({"error": "El password es obligatorio"}), 400

    username = username.strip()
    password_hash = generate_password_hash(password)

    try:
        with get_db_connection() as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            connection.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "El username ya está registrado"}), 409

    return jsonify({"message": "Usuario registrado correctamente"}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Se requiere un cuerpo JSON válido"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not username.strip():
        return jsonify({"error": "El username es obligatorio"}), 400

    if not isinstance(password, str) or not password:
        return jsonify({"error": "El password es obligatorio"}), 400

    with get_db_connection() as connection:
        user = connection.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Credenciales inválidas"}), 401

    return jsonify(
        {
            "message": "Autenticación correcta",
            "username": user["username"],
        }
    ), 200


initialize_database()

if __name__ == "__main__":
    app.run(debug=False)
