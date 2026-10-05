import sqlite3
from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = "users.db"

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

        connection = sqlite3.connect(app.config["DATABASE"])
        connection.row_factory = sqlite3.Row

        try:
            users = connection.execute(
                """
                SELECT *
                FROM users
                WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE
                """,
                (f"%{escaped_name}%",),
            ).fetchall()
        finally:
            connection.close()

        return jsonify([dict(user) for user in users])

    return app


if __name__ == "__main__":
    create_app().run()
