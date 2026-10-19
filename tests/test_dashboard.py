import sys
from datetime import datetime, timezone

sys.path.insert(0, "src/dashboard")
import app

now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
profiles = [
    {"pk": "aaaa000000000001", "firstSeen": "2026-10-18T10:00:00", "hitCount": 6,
     "decoysHit": {"admin"}, "alerted": True},
    {"pk": "bbbb000000000002", "firstSeen": "2026-10-18T11:00:00", "hitCount": 2,
     "decoysHit": {"keys", "api"}, "alerted": False},
]
hits = [
    {"pk": "aaaa000000000001", "ts": "2026-10-18T10:05:00", "decoy": "admin", "method": "POST",
     "path": "/admin", "username": "<script>alert(1)</script>", "password": "hunter2", "ip": "203.0.113.7"},
    {"pk": "bbbb000000000002", "ts": "2026-10-18T11:05:00", "decoy": "keys", "method": "GET",
     "path": "/.env", "ip": "198.51.100.9"},
]
page = app.render(profiles, hits, now)

print("shows visitors card:        ", "<b>2</b>visitors" in page)
print("shows total hits (8):       ", "<b>8</b>total hits" in page)
print("raw <script> is absent:     ", "<script>" not in page)
print("escaped version is present: ", "&lt;script&gt;" in page)
print("password never shown:       ", "hunter2" not in page)
print("IP addresses never shown:   ", "203.0.113.7" not in page and "198.51.100.9" not in page)
print("empty page renders:         ", "No visitors yet" in app.render([], [], now))
