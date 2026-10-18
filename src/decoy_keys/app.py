import json
import os
from datetime import datetime, timezone

import boto3
import honeypot_common as hc

TABLE_NAME = os.environ.get("TABLE_NAME")
TOPIC_ARN = os.environ.get("TOPIC_ARN")
_table = boto3.resource("dynamodb").Table(TABLE_NAME) if TABLE_NAME else None
_sns = boto3.client("sns") if TOPIC_ARN else None

# All values are fake. The AWS keys are the documented example values.
FAKE_ENV = (
    "APP_ENV=production\n"
    "DB_HOST=db.internal.example.com\n"
    "DB_USER=admin\n"
    "DB_PASSWORD=Example-Not-A-Real-Password\n"
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
)
FAKE_KEYS = json.dumps(
    {"environment": "production", "api_key": "key_EXAMPLE_not_real_0000", "region": "ap-southeast-2"}
)

ROUTES = {
    "/.env": ("text/plain", FAKE_ENV),
    "/api/keys": ("application/json", FAKE_KEYS),
    "/config.json": ("application/json", FAKE_KEYS),
}


def lambda_handler(event, context):
    http = event["requestContext"]["http"]
    headers = event.get("headers") or {}
    user_agent = headers.get("user-agent", "")[:200]
    path = http["path"][:200]

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "decoy": "keys",
        "fingerprint": hc.make_fingerprint(http["sourceIp"], user_agent),
        "ip": http["sourceIp"],
        "method": http["method"],
        "path": path,
        "user_agent": user_agent,
    }
    print(json.dumps(record))

    if _table is not None:
        try:
            result = hc.record_hit(_table, _sns, TOPIC_ARN, record)
            print(json.dumps({"result": result}))
        except Exception as exc:
            print(json.dumps({"error": type(exc).__name__ + ": " + str(exc)[:200]}))

    route = ROUTES.get(path.lower())
    if route:
        return {"statusCode": 200, "headers": {"Content-Type": route[0]}, "body": route[1]}
    return {"statusCode": 404, "headers": {"Content-Type": "text/plain"}, "body": "Not Found"}
