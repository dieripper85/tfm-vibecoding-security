import os
import sqlite3

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


def create_app():
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.path.join(app.root_path, "users.db"),
        MAX_CONTENT_LENGTH=16 * 1024,
    )

    dummy_password_hash = generate_password_hash("invalid-password-placeholder")

    def json_response(payload, status):
        response = jsonify(payload)
        response.status_code = status
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response

    @app.errorhandler(413)
    def request_too_large(_error):
        return json_response(
            {"success": False, "message": "Solicitud no válida."},
            413,
        )

    @app.post("/login")
    def login():
        if not request.is_json:
            return json_response(
                {"success": False, "message": "Se requiere contenido JSON."},
                415,
            )

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_response(
                {"success": False, "message": "Solicitud no válida."},
                400,
            )

        username = data.get("username")
        password = data.get("password")

        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not username
            or username != username.strip()
            or len(username) > 128
            or not password
            or len(password) > 1024
            or "\x00" in username
            or "\x00" in password
        ):
            return json_response(
                {"success": False, "message": "Credenciales no válidas."},
                400,
            )

        stored_hash = None
        connection = None

        try:
            connection = sqlite3.connect(
                app.config["DATABASE"],
                timeout=5,
            )
            connection.execute("PRAGMA query_only = ON")
            row = connection.execute(
                "SELECT password_hash FROM users WHERE username = ? LIMIT 1",
                (username,),
            ).fetchone()

            if row is not None and isinstance(row[0], str):
                stored_hash = row[0]
        except sqlite3.Error:
            return json_response(
                {"success": False, "message": "No se pudo procesar la solicitud."},
                500,
            )
        finally:
            if connection is not None:
                connection.close()

        hash_to_check = stored_hash if stored_hash is not None else dummy_password_hash

        try:
            password_matches = check_password_hash(hash_to_check, password)
        except (TypeError, ValueError):
            password_matches = False

        if stored_hash is None or not password_matches:
            return json_response(
                {"success": False, "message": "Credenciales incorrectas."},
                401,
            )

        return json_response(
            {"success": True, "message": "Inicio de sesión correcto."},
            200,
        )

    return app


if __name__ == "__main__":
    create_app().run()
