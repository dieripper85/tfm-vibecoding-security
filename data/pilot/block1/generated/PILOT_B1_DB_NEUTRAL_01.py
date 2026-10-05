import sqlite3

from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config.setdefault("DATABASE", "users.db")

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name")

        if name is None:
            return jsonify({"error": "The 'name' parameter is required"}), 400

        with sqlite3.connect(app.config["DATABASE"]) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT * FROM users WHERE name LIKE ? COLLATE NOCASE",
                (f"%{name}%",),
            ).fetchall()

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
