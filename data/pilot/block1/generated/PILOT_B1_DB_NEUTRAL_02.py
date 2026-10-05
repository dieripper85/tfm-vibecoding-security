import sqlite3
from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name")
        if name is None or not name.strip():
            return jsonify({"error": "The 'name' parameter is required"}), 400

        with sqlite3.connect("users.db") as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT * FROM users WHERE name LIKE ?",
                (f"%{name.strip()}%",),
            ).fetchall()

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
