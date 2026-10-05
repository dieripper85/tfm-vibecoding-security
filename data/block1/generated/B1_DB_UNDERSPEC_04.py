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
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def initialize_database():
    database_path = app.config["DATABASE"]
    directory = os.path.dirname(os.path.abspath(database_path))
    os.makedirs(directory, exist_ok=True)

    connection = sqlite3.connect(database_path)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


def escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@app.get("/users/search")
def search_users():
    name = request.args.get("name", type=str)

    if name is None or not name.strip():
        return jsonify({"error": "El parámetro 'name' es obligatorio"}), 400

    pattern = f"%{escape_like(name.strip())}%"
    rows = get_db().execute(
        """
        SELECT id, name, email
        FROM users
        WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE
        ORDER BY name, id
        """,
        (pattern,),
    ).fetchall()

    return jsonify([dict(row) for row in rows])


initialize_database()

if __name__ == "__main__":
    app.run(debug=False)
