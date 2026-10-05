import sqlite3
import unicodedata
from flask import Flask, current_app, g, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(DATABASE="users.db")

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(current_app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    def close_db(_error=None):
        database = g.pop("db", None)
        if database is not None:
            database.close()

    def escape_like(value):
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    @app.teardown_appcontext
    def teardown_database(error):
        close_db(error)

    @app.get("/users/search")
    def search_users():
        values = request.args.getlist("name")

        if len(values) != 1:
            return jsonify({"error": "El parámetro name es obligatorio y debe aparecer una sola vez."}), 400

        name = values[0].strip()

        if not name:
            return jsonify({"error": "El parámetro name no puede estar vacío."}), 400

        if len(name) > 100:
            return jsonify({"error": "El parámetro name no puede superar los 100 caracteres."}), 400

        if any(unicodedata.category(character) == "Cc" for character in name):
            return jsonify({"error": "El parámetro name contiene caracteres no válidos."}), 400

        pattern = f"%{escape_like(name)}%"

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
            return jsonify({"error": "No se pudo realizar la búsqueda."}), 500

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
