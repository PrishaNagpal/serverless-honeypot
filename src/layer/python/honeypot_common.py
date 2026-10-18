import hashlib
from datetime import datetime, timedelta, timezone

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

WINDOW_MINUTES = 10
WINDOW_HITS = 5
HIT_TTL_DAYS = 30


def make_fingerprint(ip, user_agent):
    raw = f"{ip}|{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _is_conditional_failure(err):
    return err.response["Error"]["Code"] == "ConditionalCheckFailedException"


def record_hit(table, sns, topic_arn, rec, now=None):
    """Store one hit, update the visitor profile, alert if a rule fires.

    Returns {"new_visitor": bool, "alert_reason": str or None}.
    """
    now = now or datetime.now(timezone.utc)
    ts = rec["ts"]
    fp = rec["fingerprint"]
    decoy = rec["decoy"]

    # 1. store the hit (30-day expiry via the table's TTL attribute)
    item = {k: v for k, v in rec.items() if v is not None}
    item.update(
        pk=fp,
        sk=f"HIT#{ts}",
        ttl=int((now + timedelta(days=HIT_TTL_DAYS)).timestamp()),
    )
    table.put_item(Item=item)

    # 2. first-seen check: only one writer can create the PROFILE item
    new_visitor = False
    try:
        table.put_item(
            Item={
                "pk": fp,
                "sk": "PROFILE",
                "firstSeen": ts,
                "hitCount": 1,
                "decoysHit": {decoy},
                "alerted": False,
                "gsi1pk": f"NEW#{now.date().isoformat()}",
                "gsi1sk": fp,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        new_visitor = True
        decoys_hit = {decoy}
    except ClientError as err:
        if not _is_conditional_failure(err):
            raise
        resp = table.update_item(
            Key={"pk": fp, "sk": "PROFILE"},
            UpdateExpression="ADD hitCount :one, decoysHit :d",
            ExpressionAttributeValues={":one": 1, ":d": {decoy}},
            ReturnValues="ALL_NEW",
        )
        decoys_hit = resp["Attributes"]["decoysHit"]

    # 3. which rule (if any) fires?
    reason = None
    if rec.get("username") is not None or rec.get("password") is not None:
        reason = "credentials submitted"
    elif decoy == "keys":
        reason = "fake key file read"
    elif len(decoys_hit) >= 2:
        reason = "multiple decoys hit"
    else:
        start = (now - timedelta(minutes=WINDOW_MINUTES)).isoformat()
        count = table.query(
            KeyConditionExpression=Key("pk").eq(fp)
            & Key("sk").between(f"HIT#{start}", f"HIT#{ts}"),
            Select="COUNT",
        )["Count"]
        if count >= WINDOW_HITS:
            reason = f"{count} hits in {WINDOW_MINUTES} minutes"

    # 4. alert at most once per visitor
    alerted_now = None
    if reason:
        try:
            table.update_item(
                Key={"pk": fp, "sk": "PROFILE"},
                UpdateExpression="SET alerted = :t",
                ConditionExpression="alerted = :f",
                ExpressionAttributeValues={":t": True, ":f": False},
            )
            sns.publish(
                TopicArn=topic_arn,
                Subject=f"Honeypot alert: {reason}",
                Message=(
                    f"Reason: {reason}\nDecoy: {decoy}\nPath: {rec.get('path')}\n"
                    f"Visitor: {fp}\nUser agent: {rec.get('user_agent')}\nTime: {ts}"
                ),
            )
            alerted_now = reason
        except ClientError as err:
            if not _is_conditional_failure(err):
                raise

    return {"new_visitor": new_visitor, "alert_reason": alerted_now}
