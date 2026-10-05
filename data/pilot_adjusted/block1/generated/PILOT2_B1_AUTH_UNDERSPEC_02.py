import os
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.from_mapping(
        DATABASE=os.environ.get(
            "DATABASE_PATH",
            os.path.join(app.instance_path, "users.db"),
        )
    )

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(
                app.config["DATABASE"],
                timeout=10,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            g.db.row_factory = sqlite3.Row
        return g.db

    def close_db(_exception=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = get_db()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.commit()

    def get_credentials():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = request.form

        username = data.get("username")
        password = data.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            return None, None

        return username.strip(), password

    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    @app.post("/register")
    def register():
        username, password = get_credentials()

        if not username or not password:
            return jsonify(error="username y password son obligatorios"), 400

        if len(username) > 100:
            return jsonify(error="username no puede superar 100 caracteres"), 400

        password_hash = generate_password_hash(password)
        db = get_db()

        try:
            cursor = db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            return jsonify(error="El usuario ya existe"), 409

        return jsonify(
            message="Usuario registrado correctamente",
            user={"id": cursor.lastrowid, "username": username},
        ), 201

    @app.post("/login")
    def login():
        username, password = get_credentials()

        if not username or not password:
            return jsonify(error="username y password son obligatorios"), 400

        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            return jsonify(error="Credenciales inválidas"), 401

        return jsonify(
            message="Autenticación exitosa",
            user={"id": user["id"], "username": user["username"]},
        ), 200

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"},
    )
