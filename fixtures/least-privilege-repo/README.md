# Least-privilege fixture

A deliberately over-broad role, plus source that only needs a fraction of it. Used by the Phase 7
tests and by the documented `remediate-iam` example.

| What | Where | Why it is here |
| --- | --- | --- |
| `infra/template.yaml` | `UploadFunctionRole.OverBroadUploadAccess` | Two wildcard statements (`s3:*`, `dynamodb:*` on `Resource: '*'`) and one already-exact statement, so the candidate has to narrow one, drop one, and leave one alone |
| `src/app.py` | literal `boto3.client` calls | The static estimate can resolve every action exactly: `s3:GetObject`, `s3:PutObject`, `sqs:SendMessage` |

This fixture contains no real credentials, no AWS accounts and no deployed resources.
