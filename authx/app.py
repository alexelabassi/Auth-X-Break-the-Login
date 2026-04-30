from __future__ import annotations

import argparse
import sqlite3
import time
import urllib.parse
from pathlib import Path

from flask import Flask, Response, current_app, g, redirect, request

from .views import (
    link_notice,
    notice,
    page_audit,
    page_dashboard,
    page_forgot,
    page_login,
    page_register,
    page_reset,
    page_tickets,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SESSION_COOKIE = "authx_session"
SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60


def utc_now() -> float:
    return time.time()


def iso_now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())


def connect(db_path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_: object | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = connect(db_path)
    try:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'USER',
                created_at TEXT NOT NULL,
                locked_until REAL NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MED', 'HIGH')),
                status TEXT NOT NULL CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED')),
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_id TEXT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                valid INTEGER NOT NULL DEFAULT 1,
                ip_address TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token TEXT,
                token_hash TEXT,
                expires_at REAL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            );
            """
        )
        db.commit()
    finally:
        db.close()


def client_ip() -> str:
    return request.remote_addr or "unknown"


def log_event(db: sqlite3.Connection, user_id: int | None, action: str, resource: str, resource_id: str | None) -> None:
    db.execute(
        """
        INSERT INTO audit_logs (user_id, action, resource, resource_id, timestamp, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, action, resource, resource_id, iso_now(), client_ip()),
    )


def current_user() -> sqlite3.Row | None:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    db = get_db()
    session = db.execute(
        """
        SELECT sessions.*, users.email, users.role
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.id = ? AND sessions.valid = 1
        """,
        (session_id,),
    ).fetchone()
    if not session:
        return None
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def create_session(db: sqlite3.Connection, user_id: int, session_id: str) -> None:
    db.execute(
        """
        INSERT OR REPLACE INTO sessions (id, user_id, created_at, expires_at, valid, ip_address)
        VALUES (?, ?, ?, ?, 1, ?)
        """,
        (session_id, user_id, utc_now(), utc_now() + SESSION_MAX_AGE_SECONDS, client_ip()),
    )


def create_app(db_path: Path) -> Flask:
    init_db(db_path)
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path
    app.teardown_appcontext(close_db)
    app.teardown_request(close_db)

    @app.get("/")
    def index() -> Response:
        return redirect("/dashboard" if current_user() else "/login", code=303)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "vulnerable"}

    @app.route("/register", methods=["GET", "POST"])
    def register() -> Response | str:
        if request.method == "GET":
            return page_register(current_user())
        db = get_db()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            return page_register(None, notice("Email and password are required.", "error"))
        try:
            cursor = db.execute(
                "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, 'USER', ?)",
                (email, password, iso_now()),
            )
            log_event(db, cursor.lastrowid, "REGISTER", "auth", str(cursor.lastrowid))
            db.commit()
        except sqlite3.IntegrityError:
            return page_register(None, notice("Email already registered.", "error"))
        return redirect("/login", code=303)

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Response | str:
        if request.method == "GET":
            return page_login(current_user())
        db = get_db()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user is None:
            return page_login(None, notice("User not found.", "error"))
        if password != user["password_hash"]:
            return page_login(None, notice("Wrong password.", "error"))
        session_id = f"session-{user['id']}"
        create_session(db, user["id"], session_id)
        log_event(db, user["id"], "LOGIN_SUCCESS", "auth", None)
        db.commit()
        response = redirect("/dashboard", code=303)
        response.set_cookie(SESSION_COOKIE, session_id, max_age=SESSION_MAX_AGE_SECONDS, path="/")
        return response

    @app.post("/logout")
    def logout() -> Response:
        db = get_db()
        user = current_user()
        session_id = request.cookies.get(SESSION_COOKIE)
        if session_id:
            db.execute("UPDATE sessions SET valid = 0 WHERE id = ?", (session_id,))
        log_event(db, user["id"] if user else None, "LOGOUT", "auth", None)
        db.commit()
        response = redirect("/login", code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.route("/forgot", methods=["GET", "POST"])
    def forgot() -> str:
        if request.method == "GET":
            return page_forgot(current_user())
        db = get_db()
        email = request.form.get("email", "").strip().lower()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user is None:
            return page_forgot(None, notice("No account for this email.", "error"))
        token = f"reset-{user['id']}"
        db.execute(
            "INSERT INTO password_reset_tokens (user_id, token, token_hash, expires_at, used, created_at) VALUES (?, ?, NULL, NULL, 0, ?)",
            (user["id"], token, utc_now()),
        )
        log_event(db, user["id"], "PASSWORD_RESET_REQUEST", "auth", None)
        db.commit()
        href = f"/reset?token={urllib.parse.quote(token)}"
        return page_forgot(None, link_notice("Lab reset link:", href, href))

    @app.route("/reset", methods=["GET", "POST"])
    def reset() -> str:
        if request.method == "GET":
            return page_reset(current_user(), request.args.get("token", ""))
        db = get_db()
        token = request.form.get("token", "")
        new_password = request.form.get("password", "")
        user = user_from_reset_token(db, token)
        if user is None:
            return page_reset(None, token, notice("Invalid reset token.", "error"))
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password, user["id"]))
        log_event(db, user["id"], "PASSWORD_RESET", "auth", None)
        db.commit()
        return page_login(None, notice("Password changed. You can log in now.", "ok"))

    @app.get("/dashboard")
    def dashboard() -> Response | str:
        user = current_user()
        if user is None:
            return redirect("/login", code=303)
        db = get_db()
        active_sessions = db.execute("SELECT COUNT(*) AS count FROM sessions WHERE user_id = ? AND valid = 1", (user["id"],)).fetchone()["count"]
        return page_dashboard(user, active_sessions)

    @app.route("/tickets", methods=["GET", "POST"])
    def tickets() -> Response | str:
        user = current_user()
        if user is None:
            return redirect("/login", code=303)
        db = get_db()
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            severity = request.form.get("severity", "LOW")
            if title and description and severity in {"LOW", "MED", "HIGH"}:
                cursor = db.execute(
                    "INSERT INTO tickets (title, description, severity, status, owner_id, created_at, updated_at) VALUES (?, ?, ?, 'OPEN', ?, ?, ?)",
                    (title[:120], description[:1000], severity, user["id"], iso_now(), iso_now()),
                )
                log_event(db, user["id"], "CREATE_TICKET", "ticket", str(cursor.lastrowid))
                db.commit()
                return redirect("/tickets", code=303)
        rows = db.execute("SELECT * FROM tickets WHERE owner_id = ? ORDER BY id DESC", (user["id"],)).fetchall()
        return page_tickets(user, rows)

    @app.get("/audit")
    def audit() -> Response | str:
        user = current_user()
        if user is None:
            return redirect("/login", code=303)
        db = get_db()
        rows = db.execute("SELECT * FROM audit_logs WHERE user_id = ? OR user_id IS NULL ORDER BY id DESC LIMIT 30", (user["id"],)).fetchall()
        return page_audit(user, rows)

    return app


def user_from_reset_token(db: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    token_row = db.execute("SELECT * FROM password_reset_tokens WHERE token = ? ORDER BY id DESC LIMIT 1", (token,)).fetchone()
    if token_row:
        return db.execute("SELECT * FROM users WHERE id = ?", (token_row["user_id"],)).fetchone()
    if token.startswith("reset-") and token[6:].isdigit():
        return db.execute("SELECT * FROM users WHERE id = ?", (int(token[6:]),)).fetchone()
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AuthX vulnerable Flask app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", type=Path, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    db_path = args.db or PROJECT_ROOT / "authx_vulnerable.db"
    app = create_app(db_path)
    print(f"AuthX vulnerable running at http://{args.host}:{args.port}")
    print(f"SQLite database: {db_path}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
