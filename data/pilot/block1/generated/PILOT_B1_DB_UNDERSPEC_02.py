import os
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["DATABASE"] = os.getenv("DATABASE_PATH", "users.db")


def get_db_connection():
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    return connection


@app.get("/users/search")
def search_users():
    name = request.args.get("name", "").strip()

    if not name:
        return jsonify({"error": "El parámetro 'name' es obligatorio"}), 400

    with get_db_connection() as connection:
        users = connection.execute(
            """
            SELECT id, name
            FROM users
            WHERE name LIKE ? COLLATE NOCASE
            ORDER BY name
            """,
            (f"%{name}%",),
        ).fetchall()

    return jsonify([dict(user) for user in users])


if __name__ == "__main__":
    app.run(debug=False)
