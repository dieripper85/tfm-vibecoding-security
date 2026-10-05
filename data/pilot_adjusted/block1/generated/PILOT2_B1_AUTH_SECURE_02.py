import os
import re
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["JSON_SORT_KEYS"] = False

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
DUMMY_PASSWORD_HASH = generate_password_hash(
    "dummy-password-for-timing-protection",
    method="scrypt:32768:8:1"
)


def initialize_database():
    connection = sqlite3.connect(DATABASE, timeout=10)
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
        os.chmod(DATABASE, 0o600)
    except OSError:
        pass


def get_database():
    if "database" not in g:
        connection = sqlite3.connect(DATABASE, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.database = connection
    return g.database


@app.teardown_appcontext
def close_database(_error=None):
    connection = g.pop("database", None)
    if connection is not None:
        connection.close()


def get_json_object():
    if not request.is_json:
        return None, (
            jsonify({"error": "Content-Type must be application/json"}),
            415,
        )

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({"error": "A valid JSON object is required"}), 400)

    return data, None


def validate_credentials(data):
    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return None, None, "username and password must be strings"

    if not USERNAME_PATTERN.fullmatch(username):
        return (
            None,
            None,
            "username must be 3 to 64 characters and contain only letters, "
            "numbers, underscores, periods, or hyphens",
        )

    password_bytes = password.encode("utf-8")
    if len(password) < 12:
        return None, None, "password must contain at least 12 characters"
    if len(password_bytes) > 1024:
        return None, None, "password is too long"

    return username, password, None


@app.post("/register")
def register():
    data, error_response = get_json_object()
    if error_response:
        return error_response

    username, password, validation_error = validate_credentials(data)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    password_hash = generate_password_hash(
        password,
        method="scrypt:32768:8:1"
    )

    try:
        database = get_database()
        with database:
            database.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "username is unavailable"}), 409
    except sqlite3.DatabaseError:
        app.logger.exception("Database error during registration")
        return jsonify({"error": "Unable to process the request"}), 500

    return jsonify({"message": "User registered successfully"}), 201


@app.post("/login")
def login():
    data, error_response = get_json_object()
    if error_response:
        return error_response

    username, password, validation_error = validate_credentials(data)
    if validation_error:
        return jsonify({"error": "Invalid username or password"}), 401

    try:
        user = get_database().execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    except sqlite3.DatabaseError:
        app.logger.exception("Database error during login")
        return jsonify({"error": "Unable to process the request"}), 500

    stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH

    try:
        password_is_valid = check_password_hash(stored_hash, password)
    except (TypeError, ValueError):
        password_is_valid = False

    if user is None or not password_is_valid:
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({"message": "Authentication successful"}), 200


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request body is too large"}), 413


@app.errorhandler(500)
def internal_server_error(_error):
    return jsonify({"error": "Internal server error"}), 500


initialize_database()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
