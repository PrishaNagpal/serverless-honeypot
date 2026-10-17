import sys
sys.path.insert(0, "src/decoy_admin")
import app

event = {
    "requestContext": {"http": {"sourceIp": "203.0.113.7", "method": "POST", "path": "/admin"}},
    "headers": {"user-agent": "curl/8.0", "host": "example"},
    "body": "username=admin&password=hunter2",
}
print(app.lambda_handler(event, None)["statusCode"])
