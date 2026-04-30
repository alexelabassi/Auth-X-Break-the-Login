from __future__ import annotations

import html
import sqlite3


def notice(message: str, kind: str = "notice") -> str:
    return f'<div class="notice {kind}">{html.escape(message)}</div>'


def link_notice(message: str, href: str, label: str) -> str:
    return (
        f'<div class="notice ok">{html.escape(message)} '
        f'<a href="{html.escape(href, quote=True)}">{html.escape(label)}</a></div>'
    )


def render_layout(title: str, body: str, user: sqlite3.Row | None) -> str:
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


def page_register(user: sqlite3.Row | None, message: str = "") -> str:
    return render_layout("Register", f"""
    <section class="panel"><h2>Register</h2>{message}
      <form action="/register" method="post">
        <label for="email">Email</label><input id="email" name="email" type="email" required>
        <label for="password">Password</label><input id="password" name="password" type="password" required>
        <button type="submit">Create account</button>
      </form>
    </section>""", user)


def page_login(user: sqlite3.Row | None, message: str = "") -> str:
    return render_layout("Login", f"""
    <section class="panel"><h2>Login</h2>{message}
      <form action="/login" method="post">
        <label for="email">Email</label><input id="email" name="email" type="email" required>
        <label for="password">Password</label><input id="password" name="password" type="password" required>
        <button type="submit">Login</button>
      </form>
    </section>""", user)


def page_forgot(user: sqlite3.Row | None, message: str = "") -> str:
    return render_layout("Forgot password", f"""
    <section class="panel"><h2>Forgot password</h2>{message}
      <form action="/forgot" method="post">
        <label for="email">Email</label><input id="email" name="email" type="email" required>
        <button type="submit">Generate reset link</button>
      </form>
    </section>""", user)


def page_reset(user: sqlite3.Row | None, token: str, message: str = "") -> str:
    safe_token = html.escape(token, quote=True)
    return render_layout("Reset password", f"""
    <section class="panel"><h2>Reset password</h2>{message}
      <form action="/reset" method="post">
        <input name="token" type="hidden" value="{safe_token}">
        <label for="token_display">Token</label><input id="token_display" value="{safe_token}" disabled>
        <label for="password">New password</label><input id="password" name="password" type="password" required>
        <button type="submit">Set new password</button>
      </form>
    </section>""", user)


def page_dashboard(user: sqlite3.Row, active_sessions: int) -> str:
    return render_layout("Dashboard", f"""
    <section class="panel">
      <h2>Dashboard</h2>
      <p>Logged in as <strong>{html.escape(user["email"])}</strong> with role <code>{html.escape(user["role"])}</code>.</p>
      <p>Active sessions: <strong>{active_sessions}</strong></p>
      <div class="grid"><a class="button" href="/tickets">Open tickets</a><a class="button" href="/audit">View audit log</a></div>
    </section>
    <section class="panel"><h3>Mode behavior</h3><p>This version contains the security fixes.</p></section>""", user)


def page_tickets(user: sqlite3.Row, rows: list[sqlite3.Row]) -> str:
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
    <section class="panel"><h2>Your tickets</h2><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Description</th></tr></thead><tbody>{table_rows or '<tr><td colspan="5" class="muted">No tickets yet.</td></tr>'}</tbody></table></section>""", user)


def page_audit(user: sqlite3.Row, rows: list[sqlite3.Row]) -> str:
    table_rows = "".join(
        f"<tr><td>{row['timestamp']}</td><td>{html.escape(row['action'])}</td><td>{html.escape(row['resource'])}</td><td>{html.escape(row['resource_id'] or '')}</td><td>{html.escape(row['ip_address'])}</td></tr>"
        for row in rows
    )
    return render_layout("Audit log", f"""
    <section class="panel"><h2>Audit log</h2><table><thead><tr><th>Time</th><th>Action</th><th>Resource</th><th>Resource ID</th><th>IP</th></tr></thead><tbody>{table_rows or '<tr><td colspan="5" class="muted">No events yet.</td></tr>'}</tbody></table></section>""", user)
