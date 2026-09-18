# ADR 0005: SAM Local, DynamoDB Local, and MinIO replace LocalStack

**Status:** Accepted

Local validation uses focused, independently maintained tools: SAM Local for
Lambda/API Gateway, DynamoDB Local for storage behavior, and MinIO for
S3-compatible objects. Components that cannot be faithfully emulated are
represented by explicit fixture data rather than implied parity.

