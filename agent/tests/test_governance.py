from dataclasses import replace

from agent.governance import Approval, Governance


def request(**changes):
    values = dict(
        action="openPR",
        tenant="alice",
        owner="alice",
        environment="production",
        source_hash="abc",
        current_hash="abc",
        proposal_id="proposal",
        validated=True,
        runtime_validated=True,
        access_safe=True,
        now=100,
    )
    values.update(changes)
    return values


def test_approval_is_required_and_bound():
    engine = Governance()
    assert engine.evaluate(**request()).outcome == "needs_human_approval"
    approval = Approval("proposal", "abc", engine.version, "alice", "production", "reviewer", 200)
    assert engine.evaluate(**request(approval=approval)).outcome == "permit"
    for altered in [
        replace(approval, expires_at=99),
        replace(approval, source_hash="changed"),
        replace(approval, policy_version="old"),
        replace(approval, proposal_id="other"),
        replace(approval, tenant="bob"),
        replace(approval, environment="development"),
    ]:
        assert engine.evaluate(**request(approval=altered)).outcome != "permit"


def test_invalid_context_and_operations_deny():
    engine = Governance()
    for changes in [
        dict(owner="bob"),
        dict(current_hash="changed"),
        dict(environment="prod"),
        dict(action="deploy"),
        dict(action="merge"),
        dict(action="directCommit"),
        dict(validated=False),
        dict(access_safe=False),
        dict(action="unknown"),
    ]:
        assert engine.evaluate(**request(**changes)).outcome == "deny"


def test_policy_errors_and_explicit_forbid_override_allow():
    assert Governance("invalid cedar").evaluate(**request()).outcome == "deny"
    engine = Governance("permit(principal, action, resource); forbid(principal, action, resource);")
    assert engine.evaluate(**request()).outcome == "deny"


def test_proposal_allowed_before_runtime_validation():
    assert Governance().evaluate(**request(action="propose", validated=False)).outcome == "permit"
