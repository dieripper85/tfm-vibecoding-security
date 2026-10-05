import os
import sqlite3
import unicodedata

from flask import Flask, current_app, g, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=os.path.join(app.root_path, "users.db"),
        MAX_NAME_LENGTH=100,
    )

    def get_db():
        if "db" not in g:
            connection = sqlite3.connect(
                current_app.config["DATABASE"],
                timeout=5,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            g.db = connection
        return g.db

    @app.teardown_appcontext
    def close_db(exception=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.get("/users/search")
    def search_users():
        values = request.args.getlist("name")

        if len(values) != 1:
            return jsonify(error="El parámetro 'name' es obligatorio y debe aparecer una sola vez."), 400

        name = unicodedata.normalize("NFC", values[0].strip())

        if not name:
            return jsonify(error="El parámetro 'name' no puede estar vacío."), 400

        if len(name) > current_app.config["MAX_NAME_LENGTH"]:
            return jsonify(error="El parámetro 'name' es demasiado largo."), 400

        if any(unicodedata.category(character) in {"Cc", "Cs"} for character in name):
            return jsonify(error="El parámetro 'name' contiene caracteres no válidos."), 400

        escaped_name = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped_name}%"

        try:
            rows = get_db().execute(
                """
                SELECT id, name
                FROM users
                WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE
                ORDER BY name, id
                """,
                (pattern,),
            ).fetchall()
        except sqlite3.Error:
            current_app.logger.exception("Error al buscar usuarios")
            return jsonify(error="No se pudo completar la búsqueda."), 500

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
