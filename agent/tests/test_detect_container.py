import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

# Only run if explicitly requested in CI/local
pytestmark = pytest.mark.skipif(
    not os.environ.get("FIRST_COMMIT_TEST_CONTAINER"),
    reason="Container tests require FIRST_COMMIT_TEST_CONTAINER=1"
)

IMAGE_NAME = "first-commit-detect-test"

@pytest.fixture(scope="module", autouse=True)
def build_container():
    """Build the container image once per test module."""
    root = Path(__file__).resolve().parents[2]
    # Build using docker directly to easily reference the image
    result = subprocess.run(
        [
            "docker", "build",
            "-t", IMAGE_NAME,
            "-f", "infra/detect.Dockerfile",
            "."
        ],
        cwd=str(root),
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        pytest.fail(f"Docker build failed:\n{result.stdout}\n{result.stderr}")


def test_container_binaries_pinned_versions():
    """Verify all three scanners are installed at the correct pinned versions."""
    
    # Check Gitleaks
    res = subprocess.run(
        ["docker", "run", "--rm", IMAGE_NAME, "gitleaks", "version"],
        capture_output=True, text=True
    )
    assert "8.21.2" in res.stdout, f"Gitleaks version mismatch: {res.stdout}"

    # Check Semgrep
    res = subprocess.run(
        ["docker", "run", "--rm", IMAGE_NAME, "semgrep", "--version"],
        capture_output=True, text=True
    )
    assert "1.100.0" in res.stdout, f"Semgrep version mismatch: {res.stdout}"

    # Check Checkov
    res = subprocess.run(
        ["docker", "run", "--rm", IMAGE_NAME, "checkov", "--version"],
        capture_output=True, text=True
    )
    assert "3.2.336" in res.stdout, f"Checkov version mismatch: {res.stdout}"


def test_python_imports_resolve():
    """Verify that the Lambda handler can be imported without missing dependencies."""
    res = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "python", IMAGE_NAME, "-c", "import api.handlers; print('OK')"],
        capture_output=True, text=True
    )
    assert "OK" in res.stdout, f"Import failed: {res.stderr}"


def test_fixture_scan_detects_all_tools(tmp_path):
    """Run a fixture scan with planted findings to prove all 3 scanners execute inside Lambda."""
    
    # We will mount a local folder into /tmp/workspace in the container, 
    # but since Lambda entrypoint expects an AWS Lambda event, we can write a small python script 
    # to invoke the adapter logic directly, or invoke the handler with a mock event.
    # To keep it simple, we invoke the agent/tools/external.py wrappers directly using python.
    
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    
    # Plant Gitleaks secret
    (repo_dir / "secret.txt").write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
    
    # Plant Semgrep unsafe command execution
    (repo_dir / "app.py").write_text("import subprocess; subprocess.Popen('ls -l', shell=True)")
    
    # Plant Checkov IAM wildcard
    (repo_dir / "template.yml").write_text(
        "Resources:\n"
        "  MyRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      AssumeRolePolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Action: '*'\n"
        "            Resource: '*'\n"
    )

    test_script = tmp_path / "run_scan.py"
    test_script.write_text(
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        "from agent.config import Settings\n"
        "from agent.tools.external import gitleaks, semgrep, checkov\n"
        "root = Path('/tmp/repo')\n"
        "settings = Settings(gitleaks_command=('/usr/local/bin/gitleaks',), semgrep_command=('/var/lang/bin/semgrep',), checkov_command=('/var/lang/bin/checkov',))\n"
        "gl_res = gitleaks(root, 'hash', settings)\n"
        "sg_res = semgrep(root, 'hash', settings)\n"
        "ck_res = checkov(root, 'hash', settings)\n"
        "print(json.dumps({\n"
        "   'gitleaks': len(gl_res.findings),\n"
        "   'semgrep': len(sg_res.findings),\n"
        "   'checkov': len(ck_res.findings)\n"
        "}))\n"
    )

    # Run the script in the container
    # Since lambda container has ENTRYPOINT mapping to aws lambda RIC, we override it to python
    res = subprocess.run(
        [
            "docker", "run", "--rm", 
            "--entrypoint", "python",
            "-v", f"{repo_dir}:/tmp/repo",
            "-v", f"{test_script}:/tmp/run_scan.py",
            IMAGE_NAME, "/tmp/run_scan.py"
        ],
        capture_output=True, text=True
    )
    
    assert res.returncode == 0, f"Scan script failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}"
    
    # The printed stdout should be the last line with json
    lines = res.stdout.strip().splitlines()
    # Find the JSON line
    counts = json.loads(lines[-1])
    
    assert counts["gitleaks"] > 0, "Gitleaks failed to detect the planted secret"
    assert counts["semgrep"] > 0, "Semgrep failed to detect the planted unsafe command"
    assert counts["checkov"] > 0, "Checkov failed to detect the planted IAM wildcard"
