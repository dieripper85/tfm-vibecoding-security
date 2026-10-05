import os
import re
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["DATABASE"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")
DUMMY_PASSWORD_HASH = generate_password_hash(
    "dummy-password-for-timing-protection",
    method="pbkdf2:sha256:600000",
)


def get_db():
    if "db" not in g:
        connection = sqlite3.connect(
            app.config["DATABASE"],
            timeout=10,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        g.db = connection
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def initialize_database():
    connection = sqlite3.connect(app.config["DATABASE"], timeout=10)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.commit()
    finally:
        connection.close()

    try:
        os.chmod(app.config["DATABASE"], 0o600)
    except OSError:
        pass


def read_json_object():
    if not request.is_json:
        return None, (jsonify({"error": "Content-Type must be application/json"}), 415)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({"error": "Invalid JSON object"}), 400)

    return data, None


def validate_credentials(data):
    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return None, None, "username and password must be strings"

    username = username.strip()

    if not USERNAME_PATTERN.fullmatch(username):
        return (
            None,
            None,
            "username must contain 3 to 50 letters, numbers, dots, underscores, or hyphens",
        )

    if len(password) < 8 or len(password) > 128:
        return None, None, "password must contain between 8 and 128 characters"

    return username, password, None


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.post("/register")
def register():
    data, error_response = read_json_object()
    if error_response is not None:
        return error_response

    username, password, validation_error = validate_credentials(data)
    if validation_error is not None:
        return jsonify({"error": validation_error}), 400

    password_hash = generate_password_hash(
        password,
        method="pbkdf2:sha256:600000",
    )

    connection = get_db()
    try:
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        connection.rollback()
        return jsonify({"error": "Username is not available"}), 409

    return jsonify({"message": "User registered successfully"}), 201


@app.post("/login")
def login():
    data, error_response = read_json_object()
    if error_response is not None:
        return error_response

    username, password, validation_error = validate_credentials(data)
    if validation_error is not None:
        return jsonify({"error": "Invalid username or password"}), 401

    row = get_db().execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    stored_hash = row["password_hash"] if row is not None else DUMMY_PASSWORD_HASH
    password_is_valid = check_password_hash(stored_hash, password)

    if row is None or not password_is_valid:
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({"message": "Authentication successful"}), 200


@app.errorhandler(Exception)
def handle_exception(error):
    if isinstance(error, HTTPException):
        status_code = error.code or 500
        messages = {
            404: "Not found",
            405: "Method not allowed",
            413: "Request body is too large",
            415: "Unsupported media type",
        }
        return jsonify({"error": messages.get(status_code, "Request failed")}), status_code

    app.logger.exception("Unhandled server error")
    return jsonify({"error": "Internal server error"}), 500


initialize_database()


if __name__ == "__main__":
    app.run(debug=False)
