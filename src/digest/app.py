import os
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key

TABLE_NAME = os.environ.get("TABLE_NAME")
TOPIC_ARN = os.environ.get("TOPIC_ARN")
MAX_ROWS = 20


def build_digest(items, day):
    """Turn the day's visitor profiles into (subject, message). Pure function."""
    total = len(items)
    per_decoy = {}
    for it in items:
        for d in it.get("decoysHit", []):
            per_decoy[d] = per_decoy.get(d, 0) + 1
    alerted = sum(1 for it in items if it.get("alerted"))

    lines = [
        f"Honeypot daily digest for {day} (UTC)",
        "",
        f"New visitors: {total}",
        f"Already alerted on: {alerted}",
        "Visitors per decoy: "
        + (", ".join(f"{k}={v}" for k, v in sorted(per_decoy.items())) or "none"),
        "",
        "Busiest visitors:",
    ]
    busiest = sorted(items, key=lambda it: int(it.get("hitCount", 0)), reverse=True)
    for it in busiest[:MAX_ROWS]:
        decoys = ",".join(sorted(it.get("decoysHit", [])))
        lines.append(
            f"- {it['pk']}  hits={int(it.get('hitCount', 0))}  decoys={decoys}"
            f"  alerted={bool(it.get('alerted'))}"
        )
    if total > MAX_ROWS:
        lines.append(f"... and {total - MAX_ROWS} more")
    return f"Honeypot daily digest: {total} new visitors", "\n".join(lines)


def fetch_new_visitors(table, day):
    items, kwargs = [], {
        "IndexName": "new-visitors",
        "KeyConditionExpression": Key("gsi1pk").eq(f"NEW#{day}"),
    }
    while True:
        resp = table.query(**kwargs)
        items.extend(resp["Items"])
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def lambda_handler(event, context):
    day = datetime.now(timezone.utc).date().isoformat()
    table = boto3.resource("dynamodb").Table(TABLE_NAME)
    items = fetch_new_visitors(table, day)
    if not items:
        print(f"digest {day}: no new visitors, nothing sent")
        return {"sent": False, "new_visitors": 0}
    subject, message = build_digest(items, day)
    boto3.client("sns").publish(TopicArn=TOPIC_ARN, Subject=subject, Message=message)
    print(f"digest {day}: sent for {len(items)} visitors")
    return {"sent": True, "new_visitors": len(items)}
