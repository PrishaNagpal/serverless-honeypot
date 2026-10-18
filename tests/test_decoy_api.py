import io
import json
import sys
from contextlib import redirect_stdout

sys.path.insert(0, "src/layer/python")
sys.path.insert(0, "src/decoy_api")
import app


def call(method, path, body=None, auth=None):
    headers = {"user-agent": "curl/8.0"}
    if auth:
        headers["authorization"] = auth
    event = {
        "requestContext": {"http": {"sourceIp": "203.0.113.7", "method": method, "path": path}},
        "headers": headers,
    }
    if body:
        event["body"] = body
    buf = io.StringIO()
    with redirect_stdout(buf):
        resp = app.lambda_handler(event, None)
    logged = json.loads(buf.getvalue().splitlines()[0])
    return resp["statusCode"], logged["username"], logged["auth"]


print("status      ", call("GET", "/api/v1/status"))
print("users no tok", call("GET", "/api/v1/users"))
print("users token ", call("GET", "/api/v1/users", auth="Bearer guess123"))
print("login json  ", call("POST", "/api/v1/login", body='{"username":"admin","password":"x"}'))
print("login junk  ", call("POST", "/api/v1/login", body="not json"))
print("unknown     ", call("GET", "/api/v2/secret"))
