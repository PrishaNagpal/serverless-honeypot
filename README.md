# HiveWatch: A Serverless Honeypot on AWS

HiveWatch is a deception network built entirely from serverless AWS services. Three fake endpoints (an admin login, a leaked-secrets file and a JSON API) sit on public URLs, record everything an attacker tries, and send email alerts when a visitor does something suspicious. A read-only dashboard shows what has been captured.

Built as a cloud architecture design project, with a focus on security design, cost control inside the AWS free tier, and operational visibility.

> **Passive only.** The honeypot never attacks back, serves only fake data, and should be deployed only in an AWS account you own.


## Architecture

```
Attacker / scanner
   |
   |-- /admin      --> decoy-admin  (Lambda + Function URL) --+
   |-- /.env ...   --> decoy-keys   (Lambda + Function URL) --+--> shared layer
   |-- /api/v1/... --> decoy-api    (Lambda + Function URL) --+    (fingerprint, alert rules)
                                                                       |
                                          +----------------------------+----------------+
                                          |                            |                |
                                     DynamoDB                    SNS (email)     CloudWatch Logs
                          (hits, visitor profiles, index)        alerts          + Logs Insights

EventBridge (daily) --> digest Lambda --> DynamoDB index --> SNS email
Browser --> dashboard Lambda (Function URL, read-only) --> DynamoDB
CloudWatch alarms (flood, throttle) --> SNS
```

Everything is defined in one CloudFormation template (`template.yaml`).

## AWS services used

| Service | Role |
|---|---|
| Lambda + Function URLs | Five functions: three decoys, a daily digest, a dashboard. Function URLs avoid API Gateway |
| DynamoDB | Stores every hit and one profile per visitor. Provisioned capacity (5 read / 5 write units) plus one index. TTL expires hits after 30 days |
| SNS | Email alerts, digests and alarm notifications |
| CloudWatch Logs, Logs Insights, Alarms | Structured JSON logs, pattern analysis, flood and throttle alarms |
| EventBridge | Daily schedule (23:55 UTC) for the digest |
| IAM | One least-privilege role per function |
| CloudFormation | Infrastructure as code |
| S3 | Holds the packaged Lambda code during deployment |

## The decoys

| Decoy | What it pretends to be | What it captures |
|---|---|---|
| `decoy-admin` | An admin login page | Usernames and passwords tried |
| `decoy-keys` | Exposed files such as `/.env` | Who goes looking for secrets |
| `decoy-api` | A half-protected JSON API under `/api/v1/` | Probing patterns, guessed tokens, login attempts |

All secrets served are fake.

## How alerts work

Each visitor is identified by a fingerprint: a short SHA-256 hash of the source IP and user agent. An alert is sent, at most once per visitor, when the first of these applies:

1. Credentials were submitted (admin login or API login)
2. The visitor touched the keys decoy
3. The same visitor hit two different decoys
4. Five or more hits within ten minutes

The once-per-visitor flag uses a DynamoDB conditional write, so simultaneous requests cannot send duplicate emails. Plain probing is logged silently and summarised in a daily digest email.

## Security design

- Each decoy has its own IAM role, log group and URL
- The dashboard role can only run `dynamodb:Query`
- Attacker-supplied values are HTML-escaped, with a strict Content-Security-Policy
- Captured passwords and IP addresses are never displayed
- Request fields are truncated before they are stored
- The alert email is a deploy-time parameter, not stored in the repo

## Cost and limits

- DynamoDB uses provisioned capacity, which also throttles floods
- Logs are kept for 14 days and hits expire after 30 days
- Every function runs with 128 MB and a short timeout
- A flood alarm (more than 300 invocations in 5 minutes) and a throttle alarm email you through SNS

Check current AWS pricing before relying on the free tier.

## Deploying

```bash
git clone https://github.com/PrishaNagpal/serverless-honeypot.git
cd serverless-honeypot

BUCKET=honeypot-artifacts-$(aws sts get-caller-identity --query Account --output text)
aws s3 mb s3://$BUCKET

aws cloudformation package --template-file template.yaml \
  --s3-bucket $BUCKET --output-template-file packaged.yaml
aws cloudformation deploy --template-file packaged.yaml \
  --stack-name honeypot-core --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides AlertEmail=you@example.com
```

Confirm the SNS subscription email from AWS, otherwise no alerts arrive. Then read the stack outputs for the decoy and dashboard URLs:

```bash
aws cloudformation describe-stacks --stack-name honeypot-core \
  --query "Stacks[0].Outputs" --output table
```

## Testing the honeypot

Send requests to your own deployment (replace the placeholders with your URLs):

```bash
# Keys decoy: request for a sensitive file
curl "<KeysUrl>/.env"

# Admin decoy: credential submission
curl -A "scanner-two" -X POST "<AdminUrl>" -d "username=admin&password=test123"

# API decoy: credential submission
curl -A "scanner-three" -X POST "<ApiUrl>/api/v1/login" \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"test123"}'
```

Using a different user agent makes each request a separate visitor, so each one triggers its own alert.

## Analysing the data

CloudWatch Logs Insights query over the decoy log groups:

```
filter ispresent(path)
| stats count(*) as hits by decoy, path
| sort hits desc
| limit 15
```


## Known limitations

- Fingerprints are unsalted hashes of IP and user agent, so visitors behind one IP with the same browser merge into one
- The Lambda concurrency limit on new accounts is shared by all functions, so a large flood can throttle the dashboard and digest. The alarms detect this but do not prevent it
- One alert per visitor: later activity is logged but not emailed
- On the AWS free plan, the account closes when the plan period ends unless upgraded

## Removing everything

```bash
BUCKET=honeypot-artifacts-$(aws sts get-caller-identity --query Account --output text)
aws cloudformation delete-stack --stack-name honeypot-core
aws s3 rb s3://$BUCKET --force
```
