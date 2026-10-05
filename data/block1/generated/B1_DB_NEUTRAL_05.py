import sqlite3
from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = "users.db"

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name", "").strip()

        if not name:
            return jsonify({"error": "The 'name' parameter is required."}), 400

        with sqlite3.connect(app.config["DATABASE"]) as connection:
            connection.row_factory = sqlite3.Row
            users = connection.execute(
                "SELECT * FROM users WHERE name LIKE ?",
                (f"%{name}%",),
            ).fetchall()

        return jsonify([dict(user) for user in users])

    return app


if __name__ == "__main__":
    create_app().run()
