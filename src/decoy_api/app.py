import base64
import json
import os
from datetime import datetime, timezone

import boto3
import honeypot_common as hc

TABLE_NAME = os.environ.get("TABLE_NAME")
TOPIC_ARN = os.environ.get("TOPIC_ARN")
_table = boto3.resource("dynamodb").Table(TABLE_NAME) if TABLE_NAME else None
_sns = boto3.client("sns") if TOPIC_ARN else None

# All data below is fake.
FAKE_USERS = [
    {"id": 1, "name": "Alex Example", "email": "alex@example.com", "role": "admin"},
    {"id": 2, "name": "Sam Sample", "email": "sam@example.com", "role": "user"},
]


def respond(status, payload):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload),
    }


def lambda_handler(event, context):
    http = event["requestContext"]["http"]
    headers = event.get("headers") or {}
    method = http["method"]
    path = http["path"][:200]
    user_agent = headers.get("user-agent", "")[:200]
    auth = headers.get("authorization", "")[:60]

    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", "replace")
    creds = {}
    if method == "POST" and body:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                creds = {k: str(data[k])[:100] for k in ("username", "password") if k in data}
        except ValueError:
            pass

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "decoy": "api",
        "fingerprint": hc.make_fingerprint(http["sourceIp"], user_agent),
        "ip": http["sourceIp"],
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "username": creds.get("username"),
        "password": creds.get("password"),
        "auth": auth or None,
    }
    print(json.dumps(record))

    if _table is not None:
        try:
            result = hc.record_hit(_table, _sns, TOPIC_ARN, record)
            print(json.dumps({"result": result}))
        except Exception as exc:
            print(json.dumps({"error": type(exc).__name__ + ": " + str(exc)[:200]}))

    route = path.lower().rstrip("/")
    if route == "/api/v1/status":
        return respond(200, {"status": "ok", "version": "2.4.1"})
    if route == "/api/v1/login" and method == "POST":
        return respond(401, {"error": "invalid credentials"})
    if route == "/api/v1/users":
        if auth:
            return respond(200, {"users": FAKE_USERS})
        return respond(401, {"error": "missing token"})
    return respond(404, {"error": "not found"})
