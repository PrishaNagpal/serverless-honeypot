import io
import json
import sys
from contextlib import redirect_stdout

sys.path.insert(0, "src/layer/python")
sys.path.insert(0, "src/decoy_keys")
import app


def call(path):
    event = {
        "requestContext": {"http": {"sourceIp": "203.0.113.7", "method": "GET", "path": path}},
        "headers": {"user-agent": "curl/8.0"},
    }
    buf = io.StringIO()
    with redirect_stdout(buf):
        resp = app.lambda_handler(event, None)
    return resp["statusCode"], json.loads(buf.getvalue().splitlines()[0])["decoy"]


for p in ("/.env", "/api/keys", "/config.json", "/wp-login.php"):
    print(p, call(p))
    