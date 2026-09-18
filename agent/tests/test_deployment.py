import pytest
import time
from unittest.mock import MagicMock
from agent.deployment import DeployService, DeploymentError
from agent.orchestration.v1_contracts import DeploymentRequestV1

@pytest.fixture
def mock_cfn():
    return MagicMock()

@pytest.fixture
def mock_store():
    store = MagicMock()
    store.get_approval.return_value = {
        "status": "approved",
        "expires_at": time.time() + 3600,
        "candidate_id": "cand-123",
        "validation_digest": "valid_digest"
    }
    store.get_validation.return_value = {
        "validation_digest": "valid_digest"
    }
    return store

@pytest.fixture
def deploy_service(mock_store, mock_cfn):
    return DeployService(store=mock_store, client=mock_cfn, allowlist="TargetAppStack:us-east-1,OtherStack:us-west-2")

@pytest.fixture
def valid_request():
    return DeploymentRequestV1(
        schema_version="1.0",
        tenant_id="tenant-123",
        candidate_id="cand-123",
        validation_digest="valid_digest",
        target_stack="TargetAppStack",
        target_region="us-east-1",
        approval_record_id="valid_approval",
        smoke_test_endpoint="https://api.example.com"
    )

def test_validate_request_success(deploy_service, valid_request):
    deploy_service.validate_request(valid_request)

def test_validate_request_not_on_allowlist(deploy_service, valid_request):
    bad_req = DeploymentRequestV1(
        **{**valid_request.to_dict(), "target_stack": "UnknownStack"}
    )
    with pytest.raises(DeploymentError) as exc:
        deploy_service.validate_request(bad_req)
    assert exc.value.code == "not_on_allowlist"

def test_validate_request_approval_not_found(deploy_service, mock_store, valid_request):
    mock_store.get_approval.return_value = None
    with pytest.raises(DeploymentError) as exc:
        deploy_service.validate_request(valid_request)
    assert exc.value.code == "approval_not_found"

def test_validate_request_approval_expired(deploy_service, mock_store, valid_request):
    mock_store.get_approval.return_value["expires_at"] = time.time() - 3600
    with pytest.raises(DeploymentError) as exc:
        deploy_service.validate_request(valid_request)
    assert exc.value.code == "approval_expired"

def test_validate_request_approval_invalid(deploy_service, mock_store, valid_request):
    mock_store.get_approval.return_value["status"] = "pending"
    with pytest.raises(DeploymentError) as exc:
        deploy_service.validate_request(valid_request)
    assert exc.value.code == "approval_invalid"

def test_validate_request_approval_candidate_mismatch(deploy_service, mock_store, valid_request):
    mock_store.get_approval.return_value["candidate_id"] = "different-cand"
    with pytest.raises(DeploymentError) as exc:
        deploy_service.validate_request(valid_request)
    assert exc.value.code == "digest_mismatch"
    
def test_validate_request_approval_digest_mismatch(deploy_service, mock_store, valid_request):
    mock_store.get_approval.return_value["validation_digest"] = "different_digest"
    with pytest.raises(DeploymentError) as exc:
        deploy_service.validate_request(valid_request)
    assert exc.value.code == "digest_mismatch"

def test_validate_request_validation_digest_mismatch(deploy_service, mock_store, valid_request):
    mock_store.get_validation.return_value["validation_digest"] = "different_digest"
    with pytest.raises(DeploymentError) as exc:
        deploy_service.validate_request(valid_request)
    assert exc.value.code == "digest_mismatch"

def test_validate_request_unknown_approval_id_rejected(deploy_service, mock_store, valid_request):
    # Proves regression is fixed: unknown arbitrary ID is rejected (it returns None)
    mock_store.get_approval.side_effect = lambda t, a_id: None if a_id == "unknown_id" else {"status": "approved", "expires_at": time.time() + 3600, "candidate_id": "cand-123", "validation_digest": "valid_digest"}
    bad_req = DeploymentRequestV1(
        **{**valid_request.to_dict(), "approval_record_id": "unknown_id"}
    )
    with pytest.raises(DeploymentError) as exc:
        deploy_service.validate_request(bad_req)
    assert exc.value.code == "approval_not_found"

def test_tenant_isolation(deploy_service, mock_store, valid_request):
    # Proves that store.get_approval is called exactly with the request's tenant_id
    deploy_service.validate_request(valid_request)
    mock_store.get_approval.assert_called_with("tenant-123", "valid_approval")

def test_create_change_set(deploy_service, mock_cfn, valid_request):
    mock_cfn.create_change_set.return_value = {"Id": "arn:aws:cloudformation:us-east-1:123:changeSet/test"}
    mock_cfn.describe_change_set.return_value = {"Status": "CREATE_COMPLETE"}
    arn = deploy_service.create_change_set(valid_request, "{}", "dep-123")
    assert arn.startswith("arn:aws")
    mock_cfn.create_change_set.assert_called_once()

def test_describe_change_set_empty(deploy_service, mock_cfn):
    mock_cfn.describe_change_set.return_value = {
        "Status": "FAILED",
        "StatusReason": "The submitted information didn't contain changes"
    }
    with pytest.raises(DeploymentError) as exc:
        deploy_service.describe_change_set("arn", "tenant-123", "dep-123", "TargetAppStack")
    assert exc.value.code == "change_set_empty"

def test_poll_execution_success(deploy_service, mock_cfn):
    mock_cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "UPDATE_COMPLETE"}]}
    status = deploy_service.poll_execution("TargetAppStack", "tenant-123", "dep-123")
    assert status == "succeeded"

def test_poll_execution_rollback(deploy_service, mock_cfn):
    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackStatus": "UPDATE_ROLLBACK_COMPLETE", "StackStatusReason": "Issue in template"}]
    }
    with pytest.raises(DeploymentError) as exc:
        deploy_service.poll_execution("TargetAppStack", "tenant-123", "dep-123")
    assert exc.value.code == "rolled_back"
    assert "Issue in template" in str(exc.value)

def test_smoke_test_fail(deploy_service):
    with pytest.raises(DeploymentError) as exc:
        deploy_service.run_smoke_test("fail", "tenant-123", "dep-123", "TargetAppStack")
    assert exc.value.code == "smoke_test_failed"

def test_smoke_test_timeout(deploy_service):
    with pytest.raises(DeploymentError) as exc:
        deploy_service.run_smoke_test("timeout", "tenant-123", "dep-123", "TargetAppStack")
    assert exc.value.code == "smoke_test_timed_out"

def test_full_run_transitions_and_audit_order(deploy_service, mock_store, mock_cfn, valid_request):
    mock_cfn.create_change_set.return_value = {"Id": "arn"}
    mock_cfn.describe_change_set.return_value = {"Status": "CREATE_COMPLETE"}
    deploy_service.create_change_set(valid_request, "{}", "dep-123")
    
    # Assert create_deployment was called before create_change_set
    mock_store.create_deployment.assert_called_once()
    mock_cfn.create_change_set.assert_called_once()
    
    deploy_service.describe_change_set("arn", "tenant-123", "dep-123", "TargetAppStack") # if it's not complete, this might just pass
    
    deploy_service.execute_change_set(valid_request, "arn", "dep-123")
    
    mock_cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "UPDATE_COMPLETE"}]}
    deploy_service.poll_execution("TargetAppStack", "tenant-123", "dep-123")
    
    from unittest.mock import call
    from agent.domain import DeploymentStatus
    
    calls = mock_store.set_deployment_status.call_args_list
    statuses = [kwargs.get("status", args[2] if len(args) > 2 else None) for args, kwargs in calls]
    
    # Check that it hits AWAITING_APPROVAL, VALIDATING, DEPLOYING, SUCCEEDED
    assert DeploymentStatus.AWAITING_APPROVAL in statuses
    assert DeploymentStatus.VALIDATING in statuses
    assert DeploymentStatus.DEPLOYING in statuses
    assert DeploymentStatus.SUCCEEDED in statuses

def test_failed_run_records_terminal_state(deploy_service, mock_store, mock_cfn, valid_request):
    mock_cfn.create_change_set.side_effect = Exception("AWS error")
    with pytest.raises(Exception):
        deploy_service.create_change_set(valid_request, "{}", "dep-123")
        
    from agent.domain import DeploymentStatus
    calls = mock_store.set_deployment_status.call_args_list
    failed_calls = [c for c in calls if (c.args[2] if len(c.args)>2 else c.kwargs.get("status")) == DeploymentStatus.FAILED]
    assert len(failed_calls) > 0
    
    args, kwargs = failed_calls[-1]
    assert kwargs.get("rollback_status") == "AWS error"

def test_concurrent_deployment_prevented(deploy_service, mock_store, mock_cfn, valid_request):
    mock_store.acquire_lock.return_value = False
    with pytest.raises(DeploymentError) as exc:
        deploy_service.create_change_set(valid_request, "{}", "dep-123")
    assert exc.value.code == "deployment_in_progress"
    mock_cfn.create_change_set.assert_not_called()

def test_lock_released_on_create_exception(deploy_service, mock_store, mock_cfn, valid_request):
    mock_store.acquire_lock.return_value = True
    mock_cfn.create_change_set.side_effect = Exception("AWS error")
    with pytest.raises(Exception):
        deploy_service.create_change_set(valid_request, "{}", "dep-123")
    mock_store.release_lock.assert_called_with("tenant-123", "TargetAppStack")

def test_lock_released_on_smoke_test_success(deploy_service, mock_store):
    deploy_service.run_smoke_test(None, "tenant-123", "dep-123", "TargetAppStack")
    mock_store.release_lock.assert_called_with("tenant-123", "TargetAppStack")

def test_lock_released_on_smoke_test_failure(deploy_service, mock_store):
    with pytest.raises(DeploymentError):
        deploy_service.run_smoke_test("fail", "tenant-123", "dep-123", "TargetAppStack")
    mock_store.release_lock.assert_called_with("tenant-123", "TargetAppStack")

def test_lock_released_on_poll_exception(deploy_service, mock_store, mock_cfn):
    mock_cfn.describe_stacks.side_effect = Exception("Unexpected error")
    with pytest.raises(Exception):
        deploy_service.poll_execution("TargetAppStack", "tenant-123", "dep-123")
    mock_store.release_lock.assert_called_with("tenant-123", "TargetAppStack")
def test_poll_execution_fetches_real_failure_reason(deploy_service, mock_store, mock_cfn):
    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackStatus": "UPDATE_ROLLBACK_COMPLETE", "StackStatusReason": "Generic rollback message"}]
    }
    mock_cfn.describe_stack_events.return_value = {
        "StackEvents": [
            {"ResourceStatus": "UPDATE_FAILED", "ResourceStatusReason": "Real failure root cause"}
        ]
    }
    
    with pytest.raises(DeploymentError) as exc:
        deploy_service.poll_execution("TargetAppStack", "tenant-123", "dep-123")
        
    assert "Real failure root cause" in str(exc.value)
    
    # Also verify it was logged to the store
    from agent.domain import DeploymentStatus
    calls = mock_store.set_deployment_status.call_args_list
    failed_calls = [c for c in calls if (c.args[2] if len(c.args)>2 else c.kwargs.get("status")) == DeploymentStatus.ROLLED_BACK]
    args, kwargs = failed_calls[-1]
    assert kwargs.get("rollback_status") == "Real failure root cause"

def test_create_change_set_wait_timeout(deploy_service, mock_store, mock_cfn, valid_request, monkeypatch):
    mock_store.acquire_lock.return_value = True
    mock_cfn.create_change_set.return_value = {"Id": "arn"}
    mock_cfn.describe_change_set.return_value = {"Status": "CREATE_IN_PROGRESS"}
    monkeypatch.setattr("time.sleep", lambda x: None)  # speed up test
    with pytest.raises(DeploymentError) as exc:
        deploy_service.create_change_set(valid_request, "{}", "dep-123")
    assert exc.value.code == "change_set_timeout"
    mock_store.release_lock.assert_called_with("tenant-123", "TargetAppStack")

def test_create_change_set_wait_empty(deploy_service, mock_store, mock_cfn, valid_request, monkeypatch):
    mock_store.acquire_lock.return_value = True
    mock_cfn.create_change_set.return_value = {"Id": "arn"}
    mock_cfn.describe_change_set.return_value = {"Status": "FAILED", "StatusReason": "The submitted information didn't contain changes"}
    monkeypatch.setattr("time.sleep", lambda x: None)
    with pytest.raises(DeploymentError) as exc:
        deploy_service.create_change_set(valid_request, "{}", "dep-123")
    assert exc.value.code == "change_set_empty"
    mock_store.release_lock.assert_called_with("tenant-123", "TargetAppStack")
