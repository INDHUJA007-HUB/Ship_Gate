import os

import boto3


def handler(event, context):
    ddb = boto3.client("dynamodb", endpoint_url=os.environ["DDB_ENDPOINT"])
    s3 = boto3.client("s3", endpoint_url=os.environ["S3_ENDPOINT"])
    item = ddb.get_item(TableName="photos", Key={"id": {"S": "demo"}})
    obj = s3.get_object(Bucket="photos", Key="demo.txt")
    return {
        "statusCode": 200,
        "title": item["Item"]["title"]["S"],
        "body": obj["Body"].read().decode(),
    }
