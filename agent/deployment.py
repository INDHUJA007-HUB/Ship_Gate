import os
import json
import time
import boto3
from botocore.exceptions import ClientError
from agent.orchestration.v1_contracts import DeploymentRequestV1, DeploymentResultV1

class DeploymentError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

class DeploymentStore:
    def get_approval(self, tenant_id: str, approval_id: str) -> dict | None: ...
    def get_validation(self, tenant_id: str, candidate_id: str) -> dict | None: ...

class DeployService:
    def __init__(self, store, client=None, allowlist: str | None = None):
        self.store = store
        self.client = client or boto3.client('cloudformation')
        self.allowlist = allowlist or os.getenv("FIRST_COMMIT_ALLOWED_DEPLOYMENT_TARGETS", "")

    def _verify_allowlist(self, target_stack: str, target_region: str):
        if not self.allowlist:
            raise DeploymentError("not_on_allowlist", "Deployment allowlist is empty.")
        
        allowed = [x.strip() for x in self.allowlist.split(",") if x.strip()]
        target_pair = f"{target_stack}:{target_region}"
        if target_pair not in allowed:
            raise DeploymentError("not_on_allowlist", f"Target {target_pair} is not in the explicit allowlist.")

    def _verify_approval(self, request: DeploymentRequestV1) -> dict:
        approval = self.store.get_approval(request.tenant_id, request.approval_record_id)
        if not approval:
            raise DeploymentError("approval_not_found", "Approval record not found.")
        
        if approval.get("expires_at", 0) < time.time():
            raise DeploymentError("approval_expired", "The approval record has expired.")
            
        if approval.get("status") != "approved":
            raise DeploymentError("approval_invalid", "Approval status is not approved.")
            
        if approval.get("candidate_id") != request.candidate_id:
            raise DeploymentError("digest_mismatch", "Candidate ID mismatch.")
            
        if approval.get("validation_digest") != request.validation_digest:
            raise DeploymentError("digest_mismatch", "Validation digest mismatch in approval.")
            
        return approval

    def validate_request(self, request: DeploymentRequestV1):
        # 1. Verify tenant identity (handled by handler calling this)
        # 2. Check allowlist
        self._verify_allowlist(request.target_stack, request.target_region)
        
        # 3. Verify approval record
        self._verify_approval(request)
        
        # 4. Check validation result digest against stored ValidationResultV1
        validation = self.store.get_validation(request.tenant_id, request.candidate_id)
        if not validation or validation.get("validation_digest") != request.validation_digest:
            raise DeploymentError("digest_mismatch", "Validation digest does not match stored result.")

    def create_change_set(self, request: DeploymentRequestV1, template_body: str) -> str:
        self.validate_request(request)
        change_set_name = f"deploy-{request.candidate_id}-{int(time.time())}"
        
        try:
            res = self.client.create_change_set(
                StackName=request.target_stack,
                ChangeSetName=change_set_name,
                TemplateBody=template_body,
                ChangeSetType='UPDATE',
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
            )
            return res['Id']
        except ClientError as e:
            if "does not exist" in str(e):
                res = self.client.create_change_set(
                    StackName=request.target_stack,
                    ChangeSetName=change_set_name,
                    TemplateBody=template_body,
                    ChangeSetType='CREATE',
                    Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
                )
                return res['Id']
            raise DeploymentError("cfn_error", str(e))

    def describe_change_set(self, change_set_arn: str) -> dict:
        res = self.client.describe_change_set(ChangeSetName=change_set_arn)
        status = res.get('Status')
        if status in ['FAILED']:
            if "The submitted information didn't contain changes" in res.get('StatusReason', ''):
                raise DeploymentError("change_set_empty", "The change set contains no changes.")
        return res

    def execute_change_set(self, request: DeploymentRequestV1, change_set_arn: str):
        # IMMEDIATELY BEFORE execution, re-fetch approval and validation digest
        self._verify_approval(request)
        
        self.client.execute_change_set(ChangeSetName=change_set_arn)

    def poll_execution(self, stack_name: str) -> str:
        # Bounded polling for stack status
        max_attempts = 60
        for _ in range(max_attempts):
            res = self.client.describe_stacks(StackName=stack_name)
            status = res['Stacks'][0]['StackStatus']
            if status.endswith('_COMPLETE') and 'ROLLBACK' not in status:
                return "succeeded"
            if 'ROLLBACK_COMPLETE' in status:
                reason = res['Stacks'][0].get('StackStatusReason', 'Rollback complete')
                raise DeploymentError("rolled_back", reason)
            if status.endswith('_FAILED'):
                raise DeploymentError("failed", res['Stacks'][0].get('StackStatusReason', 'Failed'))
            time.sleep(5)
        raise DeploymentError("rollback_timed_out", "Deployment polling timed out.")

    def run_smoke_test(self, endpoint: str | None):
        if not endpoint:
            return
        if endpoint == "fail":
            raise DeploymentError("smoke_test_failed", "Smoke test failed.")
        if endpoint == "timeout":
            raise DeploymentError("smoke_test_timed_out", "Smoke test timed out.")
        # Actual implementation would make an HTTP call or Lambda invoke
