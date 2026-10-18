import io
import json
import sys
from contextlib import redirect_stdout

sys.path.insert(0, "src/decoy_admin")
sys.path.insert(0, "src/layer/python")
import app


def run(method, ua, extra_headers=None, body=None):
    headers = {"user-agent": ua, "host": "example", **(extra_headers or {})}
    event = {
        "requestContext": {"http": {"sourceIp": "203.0.113.7", "method": method, "path": "/admin"}},
        "headers": headers,
    }
    if body:
        event["body"] = body
    buf = io.StringIO()
    with redirect_stdout(buf):
        app.lambda_handler(event, None)
    return json.loads(buf.getvalue())["fingerprint"]


get_fp = run("GET", "curl/8.0")
post_fp = run(
    "POST", "curl/8.0",
    {"content-type": "application/x-www-form-urlencoded", "content-length": "26"},
    "username=admin&password=x",
)
other_fp = run("GET", "Mozilla/5.0")

print("same client, GET == POST:", get_fp == post_fp)
print("different client differs: ", get_fp != other_fp)
