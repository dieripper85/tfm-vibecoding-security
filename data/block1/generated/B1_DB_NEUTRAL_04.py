import os
import sqlite3

from flask import Flask, g, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = os.path.abspath("users.db")

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(exception=None):
        database = g.pop("db", None)
        if database is not None:
            database.close()

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name", "").strip()
        if not name:
            return jsonify({"error": "El parámetro 'name' es obligatorio"}), 400

        escaped_name = (
            name.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )

        try:
            users = get_db().execute(
                "SELECT * FROM users WHERE name LIKE ? ESCAPE '\\'",
                (f"%{escaped_name}%",),
            ).fetchall()
        except sqlite3.Error:
            return jsonify({"error": "Error al consultar la base de datos"}), 500

        return jsonify([dict(user) for user in users])

    return app


if __name__ == "__main__":
    create_app().run()
