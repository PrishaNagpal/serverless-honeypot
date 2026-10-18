import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("AWS_DEFAULT_REGION", "ap-southeast-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

import boto3
from moto import mock_aws

sys.path.insert(0, "src/layer/python")
import honeypot_common as hc

TOPIC_NAME = "honeypot-alerts"


def setup():
    ddb = boto3.resource("dynamodb")
    table = ddb.create_table(
        TableName="honeypot-hits",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi1pk", "AttributeType": "S"},
            {"AttributeName": "gsi1sk", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "new-visitors",
                "KeySchema": [
                    {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi1sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )
    sns = boto3.client("sns")
    arn = sns.create_topic(Name=TOPIC_NAME)["TopicArn"]
    sqs = boto3.client("sqs")
    q = sqs.create_queue(QueueName="capture")["QueueUrl"]
    q_arn = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sns.subscribe(TopicArn=arn, Protocol="sqs", Endpoint=q_arn)
    return table, sns, arn, sqs, q


def hit(table, sns, arn, fp, decoy, now, offset_s=0, **extra):
    t = now + timedelta(seconds=offset_s)
    rec = {
        "ts": t.isoformat(),
        "decoy": decoy,
        "fingerprint": fp,
        "ip": "203.0.113.7",
        "method": "GET",
        "path": "/" + decoy,
        "user_agent": "test",
        **extra,
    }
    return hc.record_hit(table, sns, arn, rec, now=t)


def emails(sqs, q):
    return len(sqs.receive_message(QueueUrl=q, MaxNumberOfMessages=10).get("Messages", []))


@mock_aws
def run():
    table, sns, arn, sqs, q = setup()
    base = datetime.now(timezone.utc)

    print("--- Scenario 1: a scanner only does GETs on /admin")
    for i in range(1, 7):
        r = hit(table, sns, arn, "scanner000000001", "admin", base, offset_s=i * 30)
        print(f"hit {i}: new_visitor={r['new_visitor']} alert={r['alert_reason']}")

    print("--- Scenario 2: attacker submits credentials, then keeps trying")
    for i in range(1, 4):
        r = hit(table, sns, arn, "attacker00000002", "admin", base, offset_s=i,
                method="POST", username="admin", password=f"pw{i}")
        print(f"hit {i}: new_visitor={r['new_visitor']} alert={r['alert_reason']}")

    print("--- Scenario 3: visitor hits two different decoys")
    r1 = hit(table, sns, arn, "visitor000000003", "admin", base)
    r2 = hit(table, sns, arn, "visitor000000003", "api", base, offset_s=5)
    print(f"admin: alert={r1['alert_reason']}  api: alert={r2['alert_reason']}")

    print("--- Scenario 4: fake key file read")
    r = hit(table, sns, arn, "visitor000000004", "keys", base)
    print(f"keys: alert={r['alert_reason']}")

    print("--- Scenario 5: 5 hits spread over 40 minutes should NOT alert")
    for i in range(5):
        r = hit(table, sns, arn, "slowscanner00005", "admin", base, offset_s=i * 600)
    print(f"last alert={r['alert_reason']}")

    print("--- Totals")
    print("emails sent:", emails(sqs, q))
    prof = table.get_item(Key={"pk": "attacker00000002", "sk": "PROFILE"})["Item"]
    print("attacker profile:", {k: prof[k] for k in ("hitCount", "alerted")}, "decoysHit=", sorted(prof["decoysHit"]))
    newv = table.query(
        IndexName="new-visitors",
        KeyConditionExpression=boto3.dynamodb.conditions.Key("gsi1pk").eq(f"NEW#{base.date().isoformat()}"),
    )["Count"]
    print("new visitors today via GSI:", newv)


run()
