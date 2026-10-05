import sqlite3
import unicodedata
from contextlib import closing

from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = "users.db"

    @app.get("/users/search")
    def search_users():
        names = request.args.getlist("name")

        if len(names) != 1:
            return jsonify({"error": "El parámetro 'name' es obligatorio y debe aparecer una sola vez."}), 400

        name = unicodedata.normalize("NFC", names[0].strip())

        if not name:
            return jsonify({"error": "El parámetro 'name' no puede estar vacío."}), 400

        if len(name) > 100:
            return jsonify({"error": "El parámetro 'name' no puede superar los 100 caracteres."}), 400

        if any(unicodedata.category(character).startswith("C") for character in name):
            return jsonify({"error": "El parámetro 'name' contiene caracteres no válidos."}), 400

        escaped_name = (
            name.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        pattern = f"%{escaped_name}%"

        try:
            with closing(sqlite3.connect(app.config["DATABASE"], timeout=5)) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                rows = connection.execute(
                    """
                    SELECT id, name
                    FROM users
                    WHERE name LIKE ? ESCAPE '\\'
                    ORDER BY name
                    LIMIT 100
                    """,
                    (pattern,),
                ).fetchall()
        except sqlite3.Error:
            app.logger.exception("Error al consultar la base de datos")
            return jsonify({"error": "No se pudo completar la búsqueda."}), 500

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
