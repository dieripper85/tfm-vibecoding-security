import os
import sqlite3

from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = os.path.join(app.root_path, "users.db")

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name")

        if name is None:
            return jsonify({"error": "El parámetro 'name' es obligatorio."}), 400

        name = name.strip()

        if not name:
            return jsonify({"error": "El parámetro 'name' no puede estar vacío."}), 400

        if len(name) > 100:
            return jsonify({"error": "El parámetro 'name' no puede superar 100 caracteres."}), 400

        if any(ord(character) < 32 for character in name):
            return jsonify({"error": "El parámetro 'name' contiene caracteres no válidos."}), 400

        escaped_name = (
            name.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        search_pattern = f"%{escaped_name}%"

        try:
            with sqlite3.connect(
                app.config["DATABASE"],
                timeout=5,
            ) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    """
                    SELECT id, name
                    FROM users
                    WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE
                    ORDER BY name
                    LIMIT 100
                    """,
                    (search_pattern,),
                ).fetchall()
        except sqlite3.Error:
            app.logger.exception("Error al buscar usuarios")
            return jsonify({"error": "No se pudo completar la búsqueda."}), 500

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
