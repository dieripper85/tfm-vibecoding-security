import sqlite3
from contextlib import closing

from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)
    app.config["DATABASE"] = "users.db"

    @app.get("/users/search")
    def search_users():
        names = request.args.getlist("name")

        if len(names) != 1:
            return jsonify({"error": "The name parameter is required exactly once."}), 400

        name = names[0].strip()

        if not name:
            return jsonify({"error": "The name parameter cannot be empty."}), 400

        if len(name) > 100:
            return jsonify({"error": "The name parameter is too long."}), 400

        if "\x00" in name:
            return jsonify({"error": "The name parameter contains invalid characters."}), 400

        escaped_name = (
            name.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        search_pattern = f"%{escaped_name}%"

        try:
            with closing(
                sqlite3.connect(app.config["DATABASE"], timeout=5)
            ) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    """
                    SELECT id, name
                    FROM users
                    WHERE name LIKE ? ESCAPE '\\'
                    ORDER BY name
                    LIMIT 100
                    """,
                    (search_pattern,),
                ).fetchall()
        except sqlite3.Error:
            app.logger.exception("Database error while searching users")
            return jsonify({"error": "Unable to search users."}), 500

        return jsonify([dict(row) for row in rows])

    return app


if __name__ == "__main__":
    create_app().run()
