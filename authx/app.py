from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import re
import secrets
import sqlite3
import time
import urllib.parse
from pathlib import Path

from flask import Flask, Response, current_app, g, redirect, request


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SESSION_COOKIE = "authx_session"
SESSION_MAX_AGE_SECONDS = 30 * 60
RESET_TOKEN_MAX_AGE_SECONDS = 10 * 60
LOCK_AFTER_ATTEMPTS = 5
LOCK_SECONDS = 2 * 60
SCRYPT_N = 2**12
SCRYPT_R = 8
SCRYPT_P = 1
MIN_LOGIN_FAILURE_SECONDS = 0.2


def utc_now() -> float:
    return time.time()


def iso_now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())


def b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64encode(salt)}${b64encode(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = stored.split("$", 5)
        if algorithm != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=32,
        )
        return hmac.compare_digest(b64encode(digest), expected)
    except (TypeError, ValueError):
        return False


DUMMY_PASSWORD_HASH = hash_password("not-the-real-password")


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_valid_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]{1,80}@[^@\s]{1,120}\.[^@\s]{2,20}", email))


def password_policy_errors(password: str) -> list[str]:
    errors: list[str] = []
    if len(password) < 12:
        errors.append("minimum 12 characters")
    if not re.search(r"[a-z]", password):
        errors.append("one lowercase letter")
    if not re.search(r"[A-Z]", password):
        errors.append("one uppercase letter")
    if not re.search(r"\d", password):
        errors.append("one digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("one symbol")
    return errors


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
        "INSERT INTO audit_logs (user_id, action, resource, resource_id, timestamp, ip_address) VALUES (?, ?, ?, ?, ?, ?)",
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
    if session["expires_at"] < utc_now():
        db.execute("UPDATE sessions SET valid = 0 WHERE id = ?", (session_id,))
        db.commit()
        return None
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def create_session(db: sqlite3.Connection, user_id: int, session_id: str) -> None:
    db.execute(
        "INSERT OR REPLACE INTO sessions (id, user_id, created_at, expires_at, valid, ip_address) VALUES (?, ?, ?, ?, 1, ?)",
        (session_id, user_id, utc_now(), utc_now() + SESSION_MAX_AGE_SECONDS, client_ip()),
    )


def notice(message: str, kind: str = "notice") -> str:
    return f'<div class="notice {kind}">{html.escape(message)}</div>'


def link_notice(message: str, href: str, label: str) -> str:
    return (
        f'<div class="notice ok">{html.escape(message)} '
        f'<a href="{html.escape(href, quote=True)}">{html.escape(label)}</a></div>'
    )


def render_layout(title: str, body: str) -> str:
    user = current_user()
    nav = (
        f"""
        <form action="/logout" method="post" class="nav-actions">
            <span>{html.escape(user["email"])}</span>
            <a href="/dashboard">Dashboard</a>
            <a href="/tickets">Tickets</a>
            <button type="submit">Logout</button>
        </form>
        """
        if user
        else """
        <nav class="nav-actions">
            <a href="/login">Login</a>
            <a href="/register">Register</a>
            <a href="/forgot">Forgot password</a>
        </nav>
        """
    )
    return f"""<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} - AuthX</title>
  <style>
    :root {{ --ink: #20242a; --muted: #626b77; --line: #d9dee7; --surface: #fff; --band: #f4f7fb; --accent: #0f766e; --safe: #146c43; --danger: #b42318; font-family: Arial, Helvetica, sans-serif; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; color: var(--ink); background: var(--band); min-height: 100vh; }}
    header {{ background: var(--surface); border-bottom: 1px solid var(--line); padding: 16px clamp(18px, 5vw, 56px); display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }}
    main {{ width: min(1040px, calc(100vw - 32px)); margin: 28px auto; }}
    h1 {{ margin: 0; font-size: 26px; }} h2 {{ margin: 0 0 16px; font-size: 22px; }} h3 {{ margin: 18px 0 10px; font-size: 18px; }}
    p {{ color: var(--muted); line-height: 1.5; }} a {{ color: var(--accent); text-decoration: none; font-weight: 700; }}
    label {{ display: block; font-weight: 700; margin: 14px 0 6px; }}
    input, select, textarea {{ width: 100%; border: 1px solid #b9c1ce; border-radius: 6px; padding: 11px 12px; font: inherit; background: #fff; }}
    textarea {{ min-height: 96px; resize: vertical; }}
    button, .button {{ border: 0; border-radius: 6px; background: var(--accent); color: #fff; padding: 10px 14px; font: inherit; font-weight: 700; cursor: pointer; display: inline-block; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--surface); }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }}
    code {{ background: #edf1f6; padding: 2px 5px; border-radius: 4px; }}
    .brand {{ display: flex; align-items: baseline; gap: 12px; }}
    .badge {{ border-radius: 999px; padding: 4px 9px; color: #fff; font-size: 12px; font-weight: 700; background: var(--safe); }}
    .nav-actions {{ display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin: 0; }}
    .panel {{ background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: clamp(18px, 3vw, 28px); margin-bottom: 18px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 18px; }}
    .notice {{ border-left: 4px solid var(--accent); padding: 12px 14px; background: #eef8f6; margin-bottom: 16px; }}
    .error {{ border-left-color: var(--danger); background: #fff1f0; color: #7a271a; }}
    .ok {{ border-left-color: var(--safe); background: #eef7f1; color: #14532d; }}
    .muted {{ color: var(--muted); }}
  </style>
</head>
<body>
  <header><div class="brand"><h1>AuthX</h1><span class="badge">FIXED</span></div>{nav}</header>
  <main>{body}</main>
</body>
</html>"""


def page_register(message: str = "") -> str:
    return render_layout("Register", f"""
    <section class="panel"><h2>Register</h2>{message}
      <form action="/register" method="post">
        <label for="email">Email</label><input id="email" name="email" type="email" required>
        <label for="password">Password</label><input id="password" name="password" type="password" required>
        <button type="submit">Create account</button>
      </form>
    </section>""")


def page_login(message: str = "") -> str:
    return render_layout("Login", f"""
    <section class="panel"><h2>Login</h2>{message}
      <form action="/login" method="post">
        <label for="email">Email</label><input id="email" name="email" type="email" required>
        <label for="password">Password</label><input id="password" name="password" type="password" required>
        <button type="submit">Login</button>
      </form>
    </section>""")


def page_forgot(message: str = "") -> str:
    return render_layout("Forgot password", f"""
    <section class="panel"><h2>Forgot password</h2>{message}
      <form action="/forgot" method="post">
        <label for="email">Email</label><input id="email" name="email" type="email" required>
        <button type="submit">Generate reset link</button>
      </form>
    </section>""")


def page_reset(token: str, message: str = "") -> str:
    safe_token = html.escape(token, quote=True)
    return render_layout("Reset password", f"""
    <section class="panel"><h2>Reset password</h2>{message}
      <form action="/reset" method="post">
        <input name="token" type="hidden" value="{safe_token}">
        <label for="token_display">Token</label><input id="token_display" value="{safe_token}" disabled>
        <label for="password">New password</label><input id="password" name="password" type="password" required>
        <button type="submit">Set new password</button>
      </form>
    </section>""")


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
        return {"status": "ok", "mode": "fixed"}

    @app.route("/register", methods=["GET", "POST"])
    def register() -> Response | str:
        if request.method == "GET":
            return page_register()
        db = get_db()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not is_valid_email(email) or password_policy_errors(password):
            return page_register(notice("Registration data could not be accepted.", "error"))
        try:
            cursor = db.execute(
                "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, 'USER', ?)",
                (email, hash_password(password), iso_now()),
            )
            log_event(db, cursor.lastrowid, "REGISTER", "auth", str(cursor.lastrowid))
            db.commit()
        except sqlite3.IntegrityError:
            return page_register(notice("Registration data could not be accepted.", "error"))
        return redirect("/login", code=303)

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Response | str:
        if request.method == "GET":
            return page_login()
        started_at = utc_now()
        db = get_db()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        password_ok = verify_password(password, user["password_hash"] if user else DUMMY_PASSWORD_HASH)
        locked = bool(user and user["locked_until"] > utc_now())
        if user is None or locked or not password_ok:
            if user is not None:
                failed_attempts = int(user["failed_attempts"]) + 1
                locked_until = utc_now() + LOCK_SECONDS if failed_attempts >= LOCK_AFTER_ATTEMPTS else user["locked_until"]
                db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", (failed_attempts, locked_until, user["id"]))
                log_event(db, user["id"], "LOGIN_FAILURE", "auth", None)
            else:
                log_event(db, None, "LOGIN_FAILURE", "auth", None)
            db.commit()
            elapsed = utc_now() - started_at
            if elapsed < MIN_LOGIN_FAILURE_SECONDS:
                time.sleep(MIN_LOGIN_FAILURE_SECONDS - elapsed)
            return page_login(notice("Invalid credentials.", "error"))
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (user["id"],))
        db.execute("UPDATE sessions SET valid = 0 WHERE user_id = ?", (user["id"],))
        session_id = secrets.token_urlsafe(32)
        create_session(db, user["id"], session_id)
        log_event(db, user["id"], "LOGIN_SUCCESS", "auth", None)
        db.commit()
        response = redirect("/dashboard", code=303)
        response.set_cookie(SESSION_COOKIE, session_id, max_age=SESSION_MAX_AGE_SECONDS, path="/", httponly=True, secure=True, samesite="Strict")
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
            return page_forgot()
        db = get_db()
        email = request.form.get("email", "").strip().lower()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user is not None:
            token = secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO password_reset_tokens (user_id, token, token_hash, expires_at, used, created_at) VALUES (?, NULL, ?, ?, 0, ?)",
                (user["id"], hash_reset_token(token), utc_now() + RESET_TOKEN_MAX_AGE_SECONDS, utc_now()),
            )
            log_event(db, user["id"], "PASSWORD_RESET_REQUEST", "auth", None)
            db.commit()
            href = f"/reset?token={urllib.parse.quote(token)}"
            return page_forgot(link_notice("If the account exists, a reset link was generated. Lab link:", href, href))
        log_event(db, None, "PASSWORD_RESET_REQUEST", "auth", None)
        db.commit()
        return page_forgot(notice("If the account exists, a reset link was generated.", "ok"))

    @app.route("/reset", methods=["GET", "POST"])
    def reset() -> str:
        if request.method == "GET":
            return page_reset(request.args.get("token", ""))
        db = get_db()
        token = request.form.get("token", "")
        new_password = request.form.get("password", "")
        token_row = db.execute(
            """
            SELECT password_reset_tokens.*, users.email
            FROM password_reset_tokens
            JOIN users ON users.id = password_reset_tokens.user_id
            WHERE token_hash = ? AND used = 0 AND expires_at > ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (hash_reset_token(token), utc_now()),
        ).fetchone()
        if token_row is None:
            return page_reset(token, notice("Invalid or expired reset token.", "error"))
        if password_policy_errors(new_password):
            return page_reset(token, notice("Registration data could not be accepted.", "error"))
        db.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = 0 WHERE id = ?", (hash_password(new_password), token_row["user_id"]))
        db.execute("UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (token_row["id"],))
        db.execute("UPDATE sessions SET valid = 0 WHERE user_id = ?", (token_row["user_id"],))
        log_event(db, token_row["user_id"], "PASSWORD_RESET", "auth", None)
        db.commit()
        return page_login(notice("Password changed. You can log in now.", "ok"))

    @app.get("/dashboard")
    def dashboard() -> Response | str:
        user = current_user()
        if user is None:
            return redirect("/login", code=303)
        db = get_db()
        active_sessions = db.execute("SELECT COUNT(*) AS count FROM sessions WHERE user_id = ? AND valid = 1", (user["id"],)).fetchone()["count"]
        return render_layout("Dashboard", f"""
        <section class="panel">
          <h2>Dashboard</h2>
          <p>Logged in as <strong>{html.escape(user["email"])}</strong> with role <code>{html.escape(user["role"])}</code>.</p>
          <p>Active sessions: <strong>{active_sessions}</strong></p>
          <div class="grid"><a class="button" href="/tickets">Open tickets</a><a class="button" href="/audit">View audit log</a></div>
        </section>
        <section class="panel"><h3>Mode behavior</h3><p>This version contains the security fixes.</p></section>""")

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
        table_rows = "".join(
            f"<tr><td>{row['id']}</td><td>{html.escape(row['title'])}</td><td>{html.escape(row['severity'])}</td><td>{html.escape(row['status'])}</td><td>{html.escape(row['description'])}</td></tr>"
            for row in rows
        )
        return render_layout("Tickets", f"""
        <section class="panel"><h2>Tickets</h2>
          <form action="/tickets" method="post">
            <label for="title">Title</label><input id="title" name="title" maxlength="120" required>
            <label for="severity">Severity</label><select id="severity" name="severity"><option>LOW</option><option>MED</option><option>HIGH</option></select>
            <label for="description">Description</label><textarea id="description" name="description" maxlength="1000" required></textarea>
            <button type="submit">Create ticket</button>
          </form>
        </section>
        <section class="panel"><h2>Your tickets</h2><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Description</th></tr></thead><tbody>{table_rows or '<tr><td colspan="5" class="muted">No tickets yet.</td></tr>'}</tbody></table></section>""")

    @app.get("/audit")
    def audit() -> Response | str:
        user = current_user()
        if user is None:
            return redirect("/login", code=303)
        db = get_db()
        rows = db.execute("SELECT * FROM audit_logs WHERE user_id = ? OR user_id IS NULL ORDER BY id DESC LIMIT 30", (user["id"],)).fetchall()
        table_rows = "".join(
            f"<tr><td>{row['timestamp']}</td><td>{html.escape(row['action'])}</td><td>{html.escape(row['resource'])}</td><td>{html.escape(row['resource_id'] or '')}</td><td>{html.escape(row['ip_address'])}</td></tr>"
            for row in rows
        )
        return render_layout("Audit log", f"""
        <section class="panel"><h2>Audit log</h2><table><thead><tr><th>Time</th><th>Action</th><th>Resource</th><th>Resource ID</th><th>IP</th></tr></thead><tbody>{table_rows or '<tr><td colspan="5" class="muted">No events yet.</td></tr>'}</tbody></table></section>""")

    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AuthX secured Flask app")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--db", type=Path, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    db_path = args.db or PROJECT_ROOT / "authx_fixed.db"
    app = create_app(db_path)
    print(f"AuthX secured running at http://{args.host}:{args.port}")
    print(f"SQLite database: {db_path}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
