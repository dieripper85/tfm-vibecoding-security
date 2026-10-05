import sqlite3
from flask import Flask, current_app, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config.setdefault("DATABASE", "users.db")

    @app.get("/users/search")
    def search_users():
        names = request.args.getlist("name")

        if len(names) != 1:
            return jsonify({"error": "El parámetro name es obligatorio y debe aparecer una sola vez"}), 400

        name = names[0].strip()

        if not name:
            return jsonify({"error": "El parámetro name no puede estar vacío"}), 400

        if len(name) > 100:
            return jsonify({"error": "El parámetro name no puede superar los 100 caracteres"}), 400

        if any(ord(character) < 32 or ord(character) == 127 for character in name):
            return jsonify({"error": "El parámetro name contiene caracteres no válidos"}), 400

        escaped_name = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        search_pattern = f"%{escaped_name}%"

        try:
            with sqlite3.connect(current_app.config["DATABASE"], timeout=5) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    """
                    SELECT id, name
                    FROM users
                    WHERE name LIKE ? ESCAPE '\\'
                    ORDER BY name ASC
                    """,
                    (search_pattern,),
                ).fetchall()
        except sqlite3.Error:
            current_app.logger.exception("Error al consultar la base de datos")
            return jsonify({"error": "No se pudo completar la búsqueda"}), 500

        return jsonify([dict(row) for row in rows]), 200

    return app


if __name__ == "__main__":
    create_app().run()
