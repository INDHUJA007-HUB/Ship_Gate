from agent.code_actions import required_actions


def estimate(tmp_path, source):
    path = tmp_path / "handler.py"
    path.write_text(source, encoding="utf-8")
    return required_actions(tmp_path, [path])


def test_literal_clients_map_to_iam_actions(tmp_path):
    result = estimate(
        tmp_path,
        "import boto3\n"
        "ddb = boto3.client('dynamodb')\n"
        "s3 = boto3.client('s3')\n"
        "def handler(event, context):\n"
        "    ddb.get_item(TableName='t', Key={})\n"
        "    s3.list_objects_v2(Bucket='b')\n"
        "    s3.get_paginator('list_objects_v2')\n",
    )
    assert result.actions == ("dynamodb:GetItem", "s3:ListBucket")
    assert result.unresolved == ()
    assert result.missing_from(["dynamodb:Get*"]) == ("s3:ListBucket",)
    assert result.missing_from(["DynamoDB:getitem", "s3:ListBucket"]) == ()


def test_dynamic_and_resource_usage_is_unresolved_not_guessed(tmp_path):
    result = estimate(
        tmp_path,
        "import boto3\n"
        "name = 'sqs'\n"
        "queue = boto3.client(name)\n"
        "table = boto3.resource('dynamodb').Table('t')\n",
    )
    assert result.actions == ()
    assert result.unresolved == ("handler.py",)


def test_source_is_parsed_never_executed(tmp_path):
    result = estimate(
        tmp_path,
        "raise SystemExit('executed')\nimport boto3\nsns = boto3.client('sns')\nsns.publish()\n",
    )
    assert result.actions == ("sns:Publish",)
