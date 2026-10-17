import base64
import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs

LOGIN_PAGE = """<html><head><title>Admin Login</title></head>
<body><h2>Administrator Login</h2>
<form method="POST" action="/admin">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Sign in</button></form></body></html>"""

ERROR_PAGE = LOGIN_PAGE.replace(
    "</h2>", "</h2><p style='color:red'>Invalid credentials</p>"
)


def make_fingerprint(ip, user_agent, header_names):
    raw = f"{ip}|{user_agent}|{','.join(sorted(header_names))}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def lambda_handler(event, context):
    http = event["requestContext"]["http"]
    headers = event.get("headers") or {}
    method = http["method"]

    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", "replace")
    form = {k: v[0][:100] for k, v in parse_qs(body).items()} if method == "POST" else {}

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "decoy": "admin",
        "fingerprint": make_fingerprint(http["sourceIp"], headers.get("user-agent", ""), headers.keys()),
        "ip": http["sourceIp"],
        "method": method,
        "path": http["path"],
        "user_agent": headers.get("user-agent", "")[:200],
        "username": form.get("username"),
        "password": form.get("password"),
    }
    print(json.dumps(record))

    return {
        "statusCode": 401 if method == "POST" else 200,
        "headers": {"Content-Type": "text/html"},
        "body": ERROR_PAGE if method == "POST" else LOGIN_PAGE,
    }
    