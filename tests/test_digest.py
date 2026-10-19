import sys

sys.path.insert(0, "src/digest")
import app

items = [
    {"pk": "aaaa000000000001", "hitCount": 6, "decoysHit": {"admin"}, "alerted": True},
    {"pk": "bbbb000000000002", "hitCount": 1, "decoysHit": {"keys"}, "alerted": False},
    {"pk": "cccc000000000003", "hitCount": 3, "decoysHit": {"admin", "api"}, "alerted": True},
]
subject, message = app.build_digest(items, "2026-10-18")
print(subject)
print(message)
print("--- empty day:", app.build_digest([], "2026-10-19")[0])
