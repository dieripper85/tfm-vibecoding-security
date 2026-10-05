import os
import sqlite3
from contextlib import closing

from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash


def create_app():
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.path.join(app.root_path, "users.db"),
        MAX_CONTENT_LENGTH=16 * 1024,
        JSON_SORT_KEYS=False,
    )

    dummy_password_hash = generate_password_hash("invalid-password-placeholder")

    @app.after_request
    def set_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(_error):
        return jsonify(success=False, message="Solicitud no válida"), 413

    @app.post("/login")
    def login():
        if not request.is_json:
            return jsonify(success=False, message="Se requiere contenido JSON"), 415

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(success=False, message="Solicitud no válida"), 400

        username = data.get("username")
        password = data.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify(success=False, message="Credenciales no válidas"), 400

        if (
            not username
            or not password
            or len(username) > 150
            or len(password) > 1024
            or "\x00" in username
            or "\x00" in password
        ):
            return jsonify(success=False, message="Credenciales no válidas"), 400

        stored_hash = None

        try:
            with closing(
                sqlite3.connect(
                    app.config["DATABASE"],
                    timeout=5,
                    isolation_level=None,
                )
            ) as connection:
                cursor = connection.execute(
                    "SELECT password_hash FROM users WHERE username = ? LIMIT 1",
                    (username,),
                )
                row = cursor.fetchone()
                if row is not None and isinstance(row[0], str):
                    stored_hash = row[0]
        except sqlite3.Error:
            return jsonify(success=False, message="Servicio no disponible"), 503

        password_hash = stored_hash if stored_hash is not None else dummy_password_hash

        try:
            password_valid = check_password_hash(password_hash, password)
        except (TypeError, ValueError):
            password_valid = False

        if stored_hash is None or not password_valid:
            return jsonify(success=False, message="Usuario o contraseña incorrectos"), 401

        return jsonify(success=True, message="Inicio de sesión correcto"), 200

    return app


if __name__ == "__main__":
    create_app().run()
