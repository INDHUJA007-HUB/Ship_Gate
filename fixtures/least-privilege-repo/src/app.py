"""Fixture application for the Phase 7 estimate path.

Only literal ``boto3.client`` calls appear here, so the static estimate can resolve every action
exactly. The unresolved-input case (a ``boto3.resource`` object or a dynamic service name) is
constructed inside the tests instead, so this fixture stays a clean reference.
"""

import boto3

s3 = boto3.client("s3")
queue = boto3.client("sqs")


def upload(key, body):
    s3.put_object(Bucket="first-commit-demo", Key=key, Body=body)
    return {"stored": True}


def fetch(key):
    return s3.get_object(Bucket="first-commit-demo", Key=key)


def notify(message):
    queue.send_message(
        QueueUrl="https://sqs.us-east-1.amazonaws.com/123456789012/upload-events",
        MessageBody=message,
    )
