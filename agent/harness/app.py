import os


def handler(event, context):
    return {
        "statusCode": 200 if os.environ.get("FIRST_COMMIT_MODE") == "local" else 500,
        "body": "trusted harness",
    }
