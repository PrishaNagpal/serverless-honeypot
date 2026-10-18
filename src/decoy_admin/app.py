import base64
import json
import os
from datetime import datetime, timezone
from urllib.parse import parse_qs

import boto3
import honeypot_common as hc

TABLE_NAME = os.environ.get("TABLE_NAME")
TOPIC_ARN = os.environ.get("TOPIC_ARN")
_table = boto3.resource("dynamodb").Table(TABLE_NAME) if TABLE_NAME else None
_sns = boto3.client("sns") if TOPIC_ARN else None

LOGIN_PAGE = """<html><head><title>Admin Login</title></head>
<body><h2>Administrator Login</h2>
<form method="POST" action="/admin">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Sign in</button></form></body></html>"""

ERROR_PAGE = LOGIN_PAGE.replace(
    "</h2>", "</h2><p style='color:red'>Invalid credentials</p>"
)


def lambda_handler(event, context):
    http = event["requestContext"]["http"]
    headers = event.get("headers") or {}
    method = http["method"]
    user_agent = headers.get("user-agent", "")[:200]

    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", "replace")
    form = {k: v[0][:100] for k, v in parse_qs(body).items()} if method == "POST" else {}

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "decoy": "admin",
        "fingerprint": hc.make_fingerprint(http["sourceIp"], user_agent),
        "ip": http["sourceIp"],
        "method": method,
        "path": http["path"][:200],
        "user_agent": user_agent,
        "username": form.get("username"),
        "password": form.get("password"),
    }
    print(json.dumps(record))

    if _table is not None:
        try:
            hc.record_hit(_table, _sns, TOPIC_ARN, record)
        except Exception as exc:
            print(json.dumps({"error": str(exc)[:200]}))

    return {
        "statusCode": 401 if method == "POST" else 200,
        "headers": {"Content-Type": "text/html"},
        "body": ERROR_PAGE if method == "POST" else LOGIN_PAGE,
    }
