import sqlite3
import unicodedata
from pathlib import Path

from flask import Flask, jsonify, request


DATABASE_PATH = Path("users.db")
MAX_NAME_LENGTH = 100
MAX_RESULTS = 100


def create_app():
    app = Flask(__name__)

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name")

        if name is None:
            return jsonify({"error": "El parámetro 'name' es obligatorio."}), 400

        name = name.strip()

        if not name:
            return jsonify({"error": "El parámetro 'name' no puede estar vacío."}), 400

        if len(name) > MAX_NAME_LENGTH:
            return jsonify({
                "error": f"El parámetro 'name' no puede superar {MAX_NAME_LENGTH} caracteres."
            }), 400

        if any(unicodedata.category(char).startswith("C") for char in name):
            return jsonify({"error": "El parámetro 'name' contiene caracteres no válidos."}), 400

        escaped_name = (
            name.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        search_pattern = f"%{escaped_name}%"

        try:
            with sqlite3.connect(DATABASE_PATH) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    """
                    SELECT *
                    FROM users
                    WHERE name LIKE ? ESCAPE '\\'
                    ORDER BY name
                    LIMIT ?
                    """,
                    (search_pattern, MAX_RESULTS),
                ).fetchall()
        except sqlite3.Error:
            app.logger.exception("Error al consultar la base de datos")
            return jsonify({"error": "No se pudo completar la búsqueda."}), 500

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
