import os
import re
import sqlite3

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["JSON_SORT_KEYS"] = False

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
DUMMY_PASSWORD_HASH = generate_password_hash("dummy-password-for-timing-protection")


def get_connection():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    connection = get_connection()
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

    try:
        os.chmod(DATABASE, 0o600)
    except OSError:
        pass


def parse_credentials():
    if not request.is_json:
        return None, ("Content-Type must be application/json", 415)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, ("Invalid JSON body", 400)

    if set(data.keys()) != {"username", "password"}:
        return None, ("Exactly username and password are required", 400)

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return None, ("Username and password must be strings", 400)

    if not USERNAME_PATTERN.fullmatch(username):
        return None, (
            "Username must be 3 to 32 characters and contain only letters, numbers, underscores, or hyphens",
            400,
        )

    if len(password) < 12 or len(password) > 128:
        return None, ("Password must be between 12 and 128 characters", 400)

    if len(password.encode("utf-8")) > 512:
        return None, ("Password is too long", 400)

    return (username, password), None


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="Request body is too large"), 413


@app.errorhandler(HTTPException)
def handle_http_exception(error):
    return jsonify(error=error.name), error.code


@app.errorhandler(Exception)
def handle_unexpected_exception(_error):
    return jsonify(error="Internal server error"), 500


@app.post("/register")
def register():
    credentials, error = parse_credentials()
    if error:
        message, status = error
        return jsonify(error=message), status

    username, password = credentials
    password_hash = generate_password_hash(password)

    connection = get_connection()
    try:
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username is unavailable"), 409
    except sqlite3.DatabaseError:
        return jsonify(error="Service temporarily unavailable"), 503
    finally:
        connection.close()

    return jsonify(message="User registered successfully"), 201


@app.post("/login")
def login():
    credentials, error = parse_credentials()
    if error:
        message, status = error
        return jsonify(error=message), status

    username, password = credentials
    connection = get_connection()

    try:
        user = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    except sqlite3.DatabaseError:
        return jsonify(error="Service temporarily unavailable"), 503
    finally:
        connection.close()

    stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH

    try:
        authenticated = check_password_hash(stored_hash, password)
    except (ValueError, TypeError):
        authenticated = False

    if not user or not authenticated:
        return jsonify(error="Invalid username or password"), 401

    return jsonify(message="Authentication successful"), 200


initialize_database()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
