from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect AuthX SQLite data for lab evidence")
    parser.add_argument("--db", default="authx_vulnerable.db")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")

    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        print("Users:")
        for row in db.execute("SELECT id, email, role, password_hash, failed_attempts, locked_until FROM users ORDER BY id"):
            print(dict(row))

        print("\nReset tokens:")
        for row in db.execute("SELECT id, user_id, token, token_hash, expires_at, used FROM password_reset_tokens ORDER BY id"):
            print(dict(row))

        print("\nSessions:")
        for row in db.execute("SELECT id, user_id, expires_at, valid FROM sessions ORDER BY user_id, id"):
            print(dict(row))


if __name__ == "__main__":
    main()
