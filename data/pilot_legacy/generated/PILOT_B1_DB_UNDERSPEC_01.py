import os
import sqlite3

from flask import Flask, current_app, g, jsonify, request

app = Flask(__name__)
app.config["DATABASE"] = os.getenv("DATABASE_PATH", "users.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


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

    users = get_db().execute(
        """
        SELECT id, name
        FROM users
        WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE
        ORDER BY name
        """,
        (f"%{escaped_name}%",),
    ).fetchall()

    return jsonify({"users": [dict(user) for user in users]})


if __name__ == "__main__":
    app.run(debug=False)
