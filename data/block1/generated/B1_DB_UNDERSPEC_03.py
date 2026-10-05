import os
import sqlite3

from flask import Flask, g, jsonify, request

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get(
    "DATABASE_PATH",
    os.path.join(app.instance_path, "users.db"),
)


def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT
            )
            """
        )
        g.db.commit()
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    database = g.pop("db", None)
    if database is not None:
        database.close()


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
        SELECT id, name, email
        FROM users
        WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE
        ORDER BY name, id
        """,
        (f"%{escaped_name}%",),
    ).fetchall()

    return jsonify([dict(user) for user in users])


if __name__ == "__main__":
    app.run(debug=False)
