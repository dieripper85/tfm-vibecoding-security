import os
import sqlite3

from flask import Flask, g, jsonify, request

app = Flask(__name__)
app.config["DATABASE"] = os.getenv("DATABASE_PATH", "users.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(app.config["DATABASE"])
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT
        )
        """
    )
    db.commit()
    db.close()


def escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@app.get("/users/search")
def search_users():
    name = request.args.get("name", "").strip()
    if not name:
        return jsonify({"error": "El parámetro 'name' es obligatorio"}), 400

    pattern = f"%{escape_like(name)}%"
    users = get_db().execute(
        """
        SELECT id, name, email
        FROM users
        WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE
        ORDER BY name
        """,
        (pattern,),
    ).fetchall()

    return jsonify([dict(user) for user in users])


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
