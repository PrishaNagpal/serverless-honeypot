import html
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Key

TABLE_NAME = os.environ.get("TABLE_NAME")
DAYS = 7
TOP_VISITORS = 8
FEED_ROWS = 15
CACHE_SECONDS = 60
_cache = {"at": 0.0, "page": ""}

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

STYLE = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--card:#f4f4f2;--line:#d8d8d4;--muted:#666}
@media (prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--card:#222;--line:#3a3a3a;--muted:#999}}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:880px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:0}h2{font-size:16px;margin:24px 0 8px}
.muted{color:var(--muted);font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-top:14px}
.card{background:var(--card);border-radius:8px;padding:12px}.card b{display:block;font-size:24px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
.wrap{overflow-x:auto}code{font-family:ui-monospace,monospace}
"""


def esc(value, limit=40):
    return html.escape(str(value)[:limit])


def fetch_profiles(table, now):
    profiles = []
    for back in range(DAYS):
        day = (now - timedelta(days=back)).date().isoformat()
        kwargs = {"IndexName": "new-visitors", "KeyConditionExpression": Key("gsi1pk").eq(f"NEW#{day}")}
        while True:
            resp = table.query(**kwargs)
            profiles.extend(resp["Items"])
            if "LastEvaluatedKey" not in resp:
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return profiles


def fetch_recent_hits(table, fingerprint, limit=5):
    resp = table.query(
        KeyConditionExpression=Key("pk").eq(fingerprint) & Key("sk").begins_with("HIT#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp["Items"]


def render(profiles, hits, now):
    """profiles: PROFILE items. hits: HIT items. Returns an HTML string."""
    total_visitors = len(profiles)
    total_hits = sum(int(p.get("hitCount", 0)) for p in profiles)
    alerts = sum(1 for p in profiles if p.get("alerted"))
    per_decoy = {"admin": 0, "keys": 0, "api": 0}
    for p in profiles:
        for d in p.get("decoysHit", []):
            per_decoy[d] = per_decoy.get(d, 0) + 1

    newest = sorted(profiles, key=lambda p: p.get("firstSeen", ""), reverse=True)[:TOP_VISITORS]
    visitor_rows = "".join(
        f"<tr><td><code>{esc(p['pk'], 8)}</code></td><td>{esc(p.get('firstSeen', ''), 19)}</td>"
        f"<td>{int(p.get('hitCount', 0))}</td><td>{esc(','.join(sorted(p.get('decoysHit', []))), 30)}</td>"
        f"<td>{'yes' if p.get('alerted') else 'no'}</td></tr>"
        for p in newest
    ) or '<tr><td colspan="5" class="muted">No visitors yet</td></tr>'

    feed = sorted(hits, key=lambda h: h.get("ts", ""), reverse=True)[:FEED_ROWS]
    feed_rows = "".join(
        f"<tr><td>{esc(h.get('ts', ''), 19)}</td><td><code>{esc(h.get('pk', ''), 8)}</code></td>"
        f"<td>{esc(h.get('decoy', ''), 10)}</td><td>{esc(h.get('method', ''), 8)} {esc(h.get('path', ''), 40)}</td>"
        f"<td>{esc(h.get('username', ''), 20) if h.get('username') else ''}</td></tr>"
        for h in feed
    ) or '<tr><td colspan="5" class="muted">No activity yet</td></tr>'

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60"><title>Serverless Honeypot</title>
<style>{STYLE}</style></head><body>
<h1>Serverless Honeypot</h1>
<p class="muted">Live view of the last {DAYS} days. Updated {esc(now.strftime('%Y-%m-%d %H:%M'), 16)} UTC.
Captured passwords and IP addresses are never shown.</p>
<div class="cards">
<div class="card"><b>{total_visitors}</b>visitors</div>
<div class="card"><b>{total_hits}</b>total hits</div>
<div class="card"><b>{alerts}</b>alerts fired</div>
<div class="card"><b>{per_decoy.get('admin', 0)}</b>hit admin decoy</div>
<div class="card"><b>{per_decoy.get('keys', 0)}</b>hit keys decoy</div>
<div class="card"><b>{per_decoy.get('api', 0)}</b>hit api decoy</div>
</div>
<h2>Newest visitors</h2><div class="wrap"><table>
<tr><th>Visitor</th><th>First seen (UTC)</th><th>Hits</th><th>Decoys</th><th>Alerted</th></tr>{visitor_rows}</table></div>
<h2>Latest activity</h2><div class="wrap"><table>
<tr><th>Time (UTC)</th><th>Visitor</th><th>Decoy</th><th>Request</th><th>Username tried</th></tr>{feed_rows}</table></div>
</body></html>"""


def build_page():
    now = datetime.now(timezone.utc)
    table = boto3.resource("dynamodb").Table(TABLE_NAME)
    profiles = fetch_profiles(table, now)
    newest = sorted(profiles, key=lambda p: p.get("firstSeen", ""), reverse=True)[:TOP_VISITORS]
    hits = []
    for p in newest:
        hits.extend(fetch_recent_hits(table, p["pk"]))
    return render(profiles, hits, now)


def lambda_handler(event, context):
    if time.time() - _cache["at"] > CACHE_SECONDS or not _cache["page"]:
        _cache["page"] = build_page()
        _cache["at"] = time.time()
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": CSP,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
        "body": _cache["page"],
    }
