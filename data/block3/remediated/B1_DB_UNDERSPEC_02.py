import hmac
import os
import sqlite3
import threading
import time
from collections import deque

from flask import Flask, g, jsonify, request

app = Flask(__name__)
app.config.update(
    DATABASE=os.getenv("DATABASE_PATH", "users.db"),
    SEARCH_API_KEY=os.getenv("SEARCH_API_KEY"),
    MAX_SEARCH_LENGTH=100,
    DEFAULT_PAGE_SIZE=25,
    MAX_PAGE_SIZE=50,
    MAX_PAGE=100,
    RATE_LIMIT_REQUESTS=60,
    RATE_LIMIT_WINDOW_SECONDS=60,
)

_rate_limit_lock = threading.Lock()
_search_requests = deque()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            app.config["DATABASE"],
            timeout=5,
        )
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(app.config["DATABASE"], timeout=5) as db:
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


def escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def authenticate_request():
    configured_key = app.config.get("SEARCH_API_KEY")
    if not configured_key:
        return False, (
            jsonify({"error": "El servicio de búsqueda no está configurado"}),
            503,
        )

    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_key = authorization.partition(" ")

    if (
        not separator
        or scheme.lower() != "bearer"
        or not supplied_key
        or len(supplied_key) > 1024
    ):
        response = jsonify({"error": "Autenticación requerida"})
        response.headers["WWW-Authenticate"] = "Bearer"
        return False, (response, 401)

    try:
        valid = hmac.compare_digest(
            supplied_key.encode("utf-8"),
            str(configured_key).encode("utf-8"),
        )
    except (TypeError, UnicodeError):
        valid = False

    if not valid:
        response = jsonify({"error": "Credenciales no válidas"})
        response.headers["WWW-Authenticate"] = "Bearer"
        return False, (response, 401)

    return True, None


def check_rate_limit():
    now = time.monotonic()
    window = app.config["RATE_LIMIT_WINDOW_SECONDS"]
    limit = app.config["RATE_LIMIT_REQUESTS"]

    with _rate_limit_lock:
        cutoff = now - window
        while _search_requests and _search_requests[0] <= cutoff:
            _search_requests.popleft()

        if len(_search_requests) >= limit:
            retry_after = max(1, int(window - (now - _search_requests[0])) + 1)
            return False, retry_after

        _search_requests.append(now)

    return True, None


def parse_positive_integer(parameter, default, maximum):
    raw_value = request.args.get(parameter)
    if raw_value is None:
        return default

    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return None

    if value < 1 or value > maximum:
        return None

    return value


@app.get("/users/search")
def search_users():
    authenticated, error_response = authenticate_request()
    if not authenticated:
        return error_response

    allowed, retry_after = check_rate_limit()
    if not allowed:
        response = jsonify({"error": "Demasiadas solicitudes"})
        response.headers["Retry-After"] = str(retry_after)
        return response, 429

    name = request.args.get("name", "").strip()
    if not name:
        return jsonify({"error": "El parámetro 'name' es obligatorio"}), 400

    if len(name) > app.config["MAX_SEARCH_LENGTH"]:
        return jsonify(
            {
                "error": (
                    f"El parámetro 'name' no puede superar "
                    f"{app.config['MAX_SEARCH_LENGTH']} caracteres"
                )
            }
        ), 400

    page = parse_positive_integer("page", 1, app.config["MAX_PAGE"])
    page_size = parse_positive_integer(
        "page_size",
        app.config["DEFAULT_PAGE_SIZE"],
        app.config["MAX_PAGE_SIZE"],
    )

    if page is None:
        return jsonify({"error": "El parámetro 'page' no es válido"}), 400

    if page_size is None:
        return jsonify({"error": "El parámetro 'page_size' no es válido"}), 400

    offset = (page - 1) * page_size
    pattern = f"%{escape_like(name)}%"

    cursor = get_db().execute(
        """
        SELECT id, name, email
        FROM users
        WHERE name LIKE ? ESCAPE '\\' COLLATE NOCASE
        ORDER BY name
        LIMIT ? OFFSET ?
        """,
        (pattern, page_size, offset),
    )
    users = cursor.fetchmany(page_size)

    response = jsonify([dict(user) for user in users])
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)