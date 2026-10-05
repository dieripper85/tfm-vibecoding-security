import sqlite3

from flask import Flask, current_app, g, jsonify, request


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = "users.db"
    app.teardown_appcontext(close_db)

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name", type=str)

        if name is None or not name.strip():
            return jsonify({"error": "The name parameter is required"}), 400

        rows = get_db().execute(
            "SELECT * FROM users WHERE name LIKE ?",
            (f"%{name.strip()}%",),
        ).fetchall()

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
