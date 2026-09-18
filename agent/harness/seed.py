"""Executed inside a disposable trusted container to seed local services only.

The seed document comes from the operator's validation manifest, never from the repository.
"""

import json
import os
import time

import boto3

with open("/opt/seed.json", encoding="utf-8") as handle:
    seed = json.load(handle)
ddb = boto3.client("dynamodb", endpoint_url=os.environ["DDB_ENDPOINT"])
s3 = boto3.client("s3", endpoint_url=os.environ["S3_ENDPOINT"])
for _ in range(40):
    try:
        ddb.list_tables()
        s3.list_buckets()
        break
    except Exception:
        time.sleep(0.5)
else:
    raise SystemExit("services_not_healthy")
for table in seed.get("dynamodb", []):
    key = table["key"]
    ddb.create_table(
        TableName=table["table"],
        KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    for item in table["items"]:
        ddb.put_item(
            TableName=table["table"], Item={name: {"S": value} for name, value in item.items()}
        )
for bucket in seed.get("s3", []):
    s3.create_bucket(Bucket=bucket["bucket"])
    for key, body in bucket["objects"].items():
        s3.put_object(Bucket=bucket["bucket"], Key=key, Body=body.encode("utf-8"))
