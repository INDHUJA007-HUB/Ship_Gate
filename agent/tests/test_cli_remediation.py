import json
import subprocess
import sys
from pathlib import Path


def run(*arguments):
    return subprocess.run(
        [sys.executable, "-m", "agent.cli", *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_real_cli_proposal_and_validation(tmp_path):
    source = Path(__file__).parents[2] / "fixtures" / "iam-remediation"
    output = tmp_path / "proposal.json"
    proposal = run(
        "propose-iam",
        source,
        "policy.json",
        "--operations",
        source / "operations.json",
        "--tenant",
        "local",
        "--environment",
        "development",
        "--output",
        output,
    )
    assert proposal.returncode == 0, proposal.stderr
    assert json.loads(proposal.stdout)["status"] == "proposed"
    result = run(
        "validate-proposal", source, output, "--tenant", "local", "--environment", "development"
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["validation"]["status"] == "static_validated"
    assert report["pr_gate"]["outcome"] == "deny"
    # Fail rather than overwrite a previous review artifact.
    again = run(
        "propose-iam",
        source,
        "policy.json",
        "--operations",
        source / "operations.json",
        "--tenant",
        "local",
        "--environment",
        "development",
        "--output",
        output,
    )
    assert again.returncode == 2


def test_runtime_missing_dependencies_is_not_a_pass(monkeypatch):
    from agent.runtime_validation import validate_runtime

    monkeypatch.setattr("agent.runtime_validation.shutil.which", lambda _: None)
    result = validate_runtime()
    assert result.status == "blocked"
    assert result.errors == ("missing_dependency:sam", "missing_dependency:docker")


def test_runtime_timeout_is_explicit(monkeypatch):
    from agent.runtime_validation import validate_runtime

    monkeypatch.setattr("agent.runtime_validation.shutil.which", lambda name: name)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("docker", 120)

    monkeypatch.setattr("agent.runtime_validation.subprocess.run", timeout)
    assert validate_runtime().status == "timed_out"
