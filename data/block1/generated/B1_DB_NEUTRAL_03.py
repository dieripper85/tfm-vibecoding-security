import sqlite3

from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = "users.db"

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name")

        if name is None or not name.strip():
            return jsonify({"error": "The 'name' parameter is required."}), 400

        escaped_name = (
            name.strip()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )

        connection = sqlite3.connect(app.config["DATABASE"])
        connection.row_factory = sqlite3.Row

        try:
            rows = connection.execute(
                "SELECT * FROM users WHERE name LIKE ? ESCAPE '\\'",
                (f"%{escaped_name}%",),
            ).fetchall()
        finally:
            connection.close()

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
