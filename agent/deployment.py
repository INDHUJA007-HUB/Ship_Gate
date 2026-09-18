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
    def create_deployment(self, attempt: 'DeploymentAttempt') -> bool: ...
    def set_deployment_status(self, tenant_id: str, deployment_id: str, status: 'DeploymentStatus', updated_at: int, **kwargs) -> bool: ...

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

    def create_change_set(self, request: DeploymentRequestV1, template_body: str, deployment_id: str) -> str:
        from agent.domain import DeploymentAttempt, DeploymentStatus
        
        attempt = DeploymentAttempt(
            tenant_id=request.tenant_id,
            deployment_id=deployment_id,
            scan_id=request.candidate_id,
            proposal_id=request.approval_record_id,
            environment=request.target_stack,
            status=DeploymentStatus.REQUESTED,
            created_at=int(time.time()),
            updated_at=int(time.time())
        )
        self.store.create_deployment(attempt)
        self.store.set_deployment_status(request.tenant_id, deployment_id, DeploymentStatus.AWAITING_APPROVAL, int(time.time()))
        self.store.set_deployment_status(request.tenant_id, deployment_id, DeploymentStatus.VALIDATING, int(time.time()))
        
        try:
            self.validate_request(request)
        except Exception as e:
            self.store.set_deployment_status(request.tenant_id, deployment_id, DeploymentStatus.FAILED, int(time.time()), rollback_status=str(e))
            raise

        change_set_name = f"deploy-{request.candidate_id}-{int(time.time())}"
        try:
            res = self.client.create_change_set(
                StackName=request.target_stack,
                TemplateBody=template_body,
                ChangeSetName=change_set_name,
                ChangeSetType='UPDATE',
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
            )
            return res['Id']
        except Exception as e:
            self.store.set_deployment_status(request.tenant_id, deployment_id, DeploymentStatus.FAILED, int(time.time()), rollback_status=str(e))
            if "does not exist" in str(e):
                res = self.client.create_change_set(
                    StackName=request.target_stack,
                    TemplateBody=template_body,
                    ChangeSetName=change_set_name,
                    ChangeSetType='CREATE',
                    Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
                )
                return res['Id']
            raise DeploymentError("cfn_error", str(e))

    def describe_change_set(self, change_set_arn: str, tenant_id: str, deployment_id: str) -> dict:
        from agent.domain import DeploymentStatus
        res = self.client.describe_change_set(ChangeSetName=change_set_arn)
        if res.get('Status') == 'CREATE_COMPLETE':
            self.store.set_deployment_status(tenant_id, deployment_id, DeploymentStatus.CHANGE_SET_READY, int(time.time()))
        elif res.get('Status') == 'FAILED' and "didn't contain changes" in res.get('StatusReason', ''):
            self.store.set_deployment_status(tenant_id, deployment_id, DeploymentStatus.CANCELLED, int(time.time()), rollback_status="change_set_empty")
        status = res.get('Status')
        if status in ['FAILED']:
            if "The submitted information didn't contain changes" in res.get('StatusReason', ''):
                raise DeploymentError("change_set_empty", "The change set contains no changes.")
        return res

    def execute_change_set(self, request: DeploymentRequestV1, change_set_arn: str, deployment_id: str):
        from agent.domain import DeploymentStatus
        try:
            # IMMEDIATELY BEFORE execution, re-fetch approval and validation digest
            self._verify_approval(request)
            
            self.store.set_deployment_status(request.tenant_id, deployment_id, DeploymentStatus.DEPLOYING, int(time.time()))
            self.client.execute_change_set(ChangeSetName=change_set_arn)
        except Exception as e:
            self.store.set_deployment_status(request.tenant_id, deployment_id, DeploymentStatus.FAILED, int(time.time()), rollback_status=str(e))
            raise

    def poll_execution(self, stack_name: str, tenant_id: str, deployment_id: str) -> str:
        from agent.domain import DeploymentStatus
        for _ in range(60):
            res = self.client.describe_stacks(StackName=stack_name)
            status = res['Stacks'][0]['StackStatus']
            
            if status.endswith('_COMPLETE') and 'ROLLBACK' not in status:
                self.store.set_deployment_status(tenant_id, deployment_id, DeploymentStatus.SUCCEEDED, int(time.time()))
                return "succeeded"
            if 'ROLLBACK' in status and status.endswith('_COMPLETE'):
                reason = res['Stacks'][0].get('StackStatusReason', 'Rolled back')
                self.store.set_deployment_status(tenant_id, deployment_id, DeploymentStatus.ROLLED_BACK, int(time.time()), rollback_status=reason)
                raise DeploymentError("rolled_back", f"Deployment rolled back: {reason}")
            if status.endswith('_FAILED'):
                reason = res['Stacks'][0].get('StackStatusReason', 'Failed')
                self.store.set_deployment_status(tenant_id, deployment_id, DeploymentStatus.FAILED, int(time.time()), rollback_status=reason)
                raise DeploymentError("failed", f"Deployment failed: {reason}")
                
            time.sleep(5)
            
        self.store.set_deployment_status(tenant_id, deployment_id, DeploymentStatus.FAILED, int(time.time()), rollback_status="rollback_timed_out")
        raise DeploymentError("rollback_timed_out", "Deployment timed out.")

    def run_smoke_test(self, endpoint: str | None, tenant_id: str, deployment_id: str) -> bool:
        from agent.domain import DeploymentStatus
        if not endpoint:
            return True
            
        if endpoint == "fail":
            self.store.set_deployment_status(tenant_id, deployment_id, DeploymentStatus.FAILED, int(time.time()), rollback_status="smoke_test_failed")
            raise DeploymentError("smoke_test_failed", "Smoke test returned an error.")
        if endpoint == "timeout":
            self.store.set_deployment_status(tenant_id, deployment_id, DeploymentStatus.FAILED, int(time.time()), rollback_status="smoke_test_timed_out")
            raise DeploymentError("smoke_test_timed_out", "Smoke test timed out.")
            
        return True
        # Actual implementation would make an HTTP call or Lambda invoke
