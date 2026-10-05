import os
import re
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import BadRequest, HTTPException, RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
DUMMY_PASSWORD_HASH = generate_password_hash("dummy-password-for-timing-protection", method="scrypt")


def get_db():
    if "db" not in g:
        connection = sqlite3.connect(DATABASE, timeout=10)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        g.db = connection
    return g.db


def initialize_database():
    connection = sqlite3.connect(DATABASE, timeout=10)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
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


def parse_json_body():
    if not request.is_json:
        return None, (jsonify({"error": "Content-Type must be application/json"}), 415)

    try:
        data = request.get_json()
    except BadRequest:
        return None, (jsonify({"error": "Invalid JSON"}), 400)

    if not isinstance(data, dict):
        return None, (jsonify({"error": "JSON body must be an object"}), 400)

    return data, None


def validate_credentials(data):
    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return None, None, "username and password must be strings"

    username = username.strip()

    if not USERNAME_PATTERN.fullmatch(username):
        return None, None, (
            "username must be 3 to 64 characters and contain only letters, "
            "numbers, dots, underscores, or hyphens"
        )

    if len(password) < 8 or len(password) > 128:
        return None, None, "password must be between 8 and 128 characters"

    return username, password, None


@app.teardown_appcontext
def close_db(_exception=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


@app.post("/register")
def register():
    data, error_response = parse_json_body()
    if error_response:
        return error_response

    username, password, validation_error = validate_credentials(data)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    password_hash = generate_password_hash(password, method="scrypt")
    connection = get_db()

    try:
        with connection:
            connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username is not available"}), 409
    except sqlite3.DatabaseError:
        return jsonify({"error": "Unable to process the request"}), 500

    return jsonify({"message": "User registered successfully"}), 201


@app.post("/login")
def login():
    data, error_response = parse_json_body()
    if error_response:
        return error_response

    username, password, validation_error = validate_credentials(data)
    if validation_error:
        return jsonify({"error": "Invalid username or password"}), 401

    try:
        row = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    except sqlite3.DatabaseError:
        return jsonify({"error": "Unable to process the request"}), 500

    stored_hash = row[0] if row else DUMMY_PASSWORD_HASH
    password_is_valid = check_password_hash(stored_hash, password)

    if row is None or not password_is_valid:
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({"message": "Authentication successful"}), 200


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(_error):
    return jsonify({"error": "Request body is too large"}), 413


@app.errorhandler(HTTPException)
def handle_http_exception(error):
    return jsonify({"error": error.name}), error.code


@app.errorhandler(Exception)
def handle_unexpected_error(_error):
    return jsonify({"error": "Internal server error"}), 500


initialize_database()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
