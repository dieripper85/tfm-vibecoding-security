import sqlite3

from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = "users.db"

    @app.post("/login")
    def login():
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify(success=False, message="JSON inválido"), 400

        username = data.get("username")
        password = data.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify(
                success=False,
                message="username y password son obligatorios",
            ), 400

        try:
            with sqlite3.connect(app.config["DATABASE"]) as connection:
                user = connection.execute(
                    """
                    SELECT 1
                    FROM users
                    WHERE username = ? AND password = ?
                    LIMIT 1
                    """,
                    (username, password),
                ).fetchone()
        except sqlite3.Error:
            app.logger.exception("Error al consultar la base de datos")
            return jsonify(
                success=False,
                message="Error interno del servidor",
            ), 500

        if user is None:
            return jsonify(
                success=False,
                message="Credenciales incorrectas",
            ), 401

        return jsonify(
            success=True,
            message="Inicio de sesión correcto",
        ), 200

    return app


if __name__ == "__main__":
    create_app().run()
