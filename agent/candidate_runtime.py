"""Disposable candidate runtime on an internal Docker network; the host never imports source.

This is the only place candidate code runs: inside locked-down containers from pinned images, on
a network with no route out. The event, expected response and seed data are trusted operator
input from a manifest kept outside the submitted repository.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from threading import Event

from agent.config import Settings
from agent.governance import Approval, Governance
from agent.policy_documents import load_document
from agent.preflight import inspect_tree
from agent.remediation import Proposal, validate_proposal
from agent.scan import ScanService
from agent.toolchain import executable, local_environment

IMAGES = {
    "lambda": "public.ecr.aws/lambda/python"
    "@sha256:c80ddbecefef4a22ba73edde94280f84201a5208dea33f4d8e6a8267bb531488",
    "ddb": "amazon/dynamodb-local"
    "@sha256:ff89bd48ff32cd8d9be5fee8873b65b8854dc408f1afe881be6eb00247bc0dab",
    "minio": "quay.io/minio/minio"
    "@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e",
}
HARNESS = Path(__file__).parent / "harness"
MANIFEST_KEYS = {"template", "function", "event", "expected", "environment", "seed"}
DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "Pipfile",
    "poetry.lock",
    "Makefile",
}
LOCKDOWN = (
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--cpus",
    "1",
    "--memory",
    "512m",
    "--pids-limit",
    "128",
    "--log-opt",
    "max-size=1m",
    "--log-opt",
    "max-file=1",
)
RESPONSE_MARKER = "FIRST_COMMIT_RESPONSE "
LOCAL_CREDENTIALS = {
    "AWS_ACCESS_KEY_ID": "localtest",
    "AWS_SECRET_ACCESS_KEY": "localtest123",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_EC2_METADATA_DISABLED": "true",
}


class RuntimeFailure(Exception):
    pass


def _text(value, limit):
    return isinstance(value, str) and 0 < len(value) <= limit


def check_manifest(manifest) -> dict:
    """Validate the operator manifest; seed data stays a small, declarative local operation."""
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        raise RuntimeFailure("invalid_validation_manifest")
    seed = manifest["seed"]
    try:
        tables, buckets = seed.get("dynamodb", []), seed.get("s3", [])
        valid = (
            not set(seed) - {"dynamodb", "s3"}
            and len(tables) <= 10
            and len(buckets) <= 10
            and all(
                set(table) == {"table", "key", "items"}
                and _text(table["table"], 255)
                and _text(table["key"], 255)
                and len(table["items"]) <= 100
                and all(
                    table["key"] in item
                    and all(_text(k, 255) and _text(v, 4096) for k, v in item.items())
                    for item in table["items"]
                )
                for table in tables
            )
            and all(
                set(bucket) == {"bucket", "objects"}
                and _text(bucket["bucket"], 63)
                and len(bucket["objects"]) <= 100
                and all(_text(k, 1024) and _text(v, 65536) for k, v in bucket["objects"].items())
                for bucket in buckets
            )
        )
    except (AttributeError, TypeError, KeyError):
        valid = False
    if not valid:
        raise RuntimeFailure("invalid_seed")
    return manifest


def contract(root: Path, manifest: dict, files) -> str:
    """Accept only the packaging this runtime reproduces faithfully; return the handler."""
    manifest = check_manifest(manifest)
    if manifest["template"] not in {"template.yaml", "template.yml", "template.json"}:
        raise RuntimeFailure("unsupported_template_path")
    if any(path.name in DEPENDENCY_FILES for path in files):
        raise RuntimeFailure("custom_dependency_build_requires_review")
    template = load_document((root / manifest["template"]).read_text(encoding="utf-8"))
    resource = template.get("Resources", {}).get(manifest["function"])
    if not isinstance(resource, dict) or resource.get("Type") != "AWS::Serverless::Function":
        raise RuntimeFailure("function_not_found")
    props = resource.get("Properties", {})
    if props.get("Runtime") != "python3.12":
        raise RuntimeFailure("unsupported_lambda_runtime")
    if (
        props.get("CodeUri", ".") != "."
        or props.get("Layers")
        or props.get("PackageType", "Zip") != "Zip"
    ):
        raise RuntimeFailure("unsupported_lambda_packaging")
    if props.get("Architectures", ["x86_64"]) != ["x86_64"]:
        raise RuntimeFailure("unsupported_lambda_architecture")
    handler = props.get("Handler", "")
    if len(handler.split(".")) != 2 or not all(p.isidentifier() for p in handler.split(".")):
        raise RuntimeFailure("unsupported_handler")
    environment = manifest["environment"]
    declared = props.get("Environment", {}).get("Variables", {})
    if environment != declared or not all(isinstance(v, str) for v in environment.values()):
        raise RuntimeFailure("environment_contract_mismatch")
    if any(
        k.startswith("AWS_") or k in {"PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH"}
        for k in environment
    ):
        raise RuntimeFailure("reserved_environment_variable")
    return handler


class CandidateRuntime:
    def __init__(
        self,
        timeout: int = 300,
        cancel: Event | None = None,
        settings: Settings | None = None,
        scanner: ScanService | None = None,
    ):
        self.timeout = timeout
        self.cancel = cancel or Event()
        self.settings = settings or Settings.from_env()
        self.scanner = scanner or ScanService(self.settings)
        self.audit: list[dict] = []
        self.deadline = 0.0

    def command(self, args, *, check=True, cleanup=False, cwd=None):
        if not cleanup and self.cancel.is_set():
            raise RuntimeFailure("cancelled")
        remaining = 30 if cleanup else min(120, self.deadline - time.monotonic())
        if remaining <= 0:
            raise RuntimeFailure("timed_out")
        started = time.monotonic()
        # Bound output on disk and in memory; raw runtime logs are never published.
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                args,
                cwd=cwd,
                env=local_environment(),
                stdout=output,
                stderr=subprocess.STDOUT,
                shell=False,
            )
            while process.poll() is None:
                if (
                    time.monotonic() - started > remaining
                    or (not cleanup and self.cancel.is_set())
                    or output.tell() > 1024 * 1024
                ):
                    process.kill()
                    process.wait()
                    raise RuntimeFailure("cancelled" if self.cancel.is_set() else "timed_out")
                time.sleep(0.05)
            output.seek(0)
            data = output.read(1024 * 1024)
        self.audit.append(
            {
                "tool": Path(args[0]).name,
                "operation": args[1],
                "exit_code": process.returncode,
                "duration_seconds": round(time.monotonic() - started, 3),
                "output_sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        if check and process.returncode:
            raise RuntimeFailure(f"{Path(args[0]).stem}_{args[1]}_failed")
        return data.decode("utf-8", errors="replace").strip(), process.returncode

    def _replay_scanners(self, original: Path, candidate: Path, proposal: Proposal, details):
        before, after = self.scanner.scan(original), self.scanner.scan(candidate)
        if not (before.complete and after.complete):
            raise RuntimeFailure("scanner_replay_incomplete")

        def keys(report):
            return {
                (item.finding_type.value, item.location.path, item.evidence.rule_id)
                for item in report.findings
            }

        # Line numbers shift in a rewritten file, so compare category, path and rule.
        introduced = sorted(keys(after) - keys(before))
        if introduced:
            details["introduced_findings"] = [list(item) for item in introduced]
            raise RuntimeFailure("candidate_introduces_findings")
        if any(
            f.finding_type == "iam_wildcard" and f.location.path == proposal.target
            for f in after.findings
        ):
            raise RuntimeFailure("iam_finding_not_resolved")

    def _launch(self, containers, name, network, image, arguments=(), extra=(), detach=True):
        containers.append(name)
        return self.command(
            [
                executable("docker"),
                "run",
                *(("--detach",) if detach else ()),
                "--name",
                name,
                "--network",
                network,
                *LOCKDOWN,
                *extra,
                image,
                *arguments,
            ],
            check=detach,
        )

    def validate(
        self,
        source: Path,
        proposal: Proposal,
        manifest: dict,
        *,
        tenant: str,
        environment: str,
        approval: Approval | None = None,
    ) -> dict:
        self.deadline = time.monotonic() + self.timeout
        self.audit = []
        status, errors, checks, details, images = "failed", [], [], {}, {}
        candidate_hash = None
        docker = executable("docker")
        prefix = "fc-" + uuid.uuid4().hex[:16]
        created_network, containers = False, []
        try:
            if self.cancel.is_set():
                raise RuntimeFailure("cancelled")
            check_manifest(manifest)
            result = validate_proposal(source, proposal, tenant=tenant, environment=environment)
            if result.status != "static_validated":
                raise RuntimeFailure(result.errors[0])
            checks.extend(result.checks)
            self.command([docker, "info", "--format", "{{.ServerVersion}}"])
            for key, image in IMAGES.items():
                digest, _ = self.command([docker, "image", "inspect", image, "--format", "{{.Id}}"])
                if not digest.startswith("sha256:"):
                    raise RuntimeFailure("image_not_available")
                images[key] = digest  # Immutable image IDs are used for the whole run.
            with tempfile.TemporaryDirectory(
                prefix="first-commit-candidate-", ignore_cleanup_errors=True
            ) as temporary:
                work = Path(temporary)
                original, root = work / "original", work / "candidate"
                shutil.copytree(source, original, symlinks=True)
                # Revalidate the snapshot, including symlinks and concurrent source changes.
                snapshot = validate_proposal(
                    original, proposal, tenant=tenant, environment=environment
                )
                if snapshot.status != "static_validated":
                    raise RuntimeFailure("snapshot_changed")
                shutil.copytree(original, root, symlinks=True)
                # Bytes, not text: newline translation would alter the reviewed replacement.
                (root / proposal.target).write_bytes(proposal.replacement.encode("utf-8"))
                preflight = inspect_tree(root, self.settings.limits)
                candidate_hash = preflight.content_hash
                handler = contract(root, manifest, preflight.files)
                checks.append("candidate_patch_applied")
                self._replay_scanners(original, root, proposal, details)
                checks.append("scanner_replay_no_new_findings")
                # Trusted working directory: a repository samconfig.toml must not apply.
                self.command(
                    [
                        executable("sam"),
                        "validate",
                        "--template-file",
                        str(root / manifest["template"]),
                        "--region",
                        "us-east-1",
                    ],
                    cwd=work,
                )
                checks.append("sam_template_validated")

                self.command([docker, "network", "create", "--internal", prefix])
                created_network = True
                (work / "seed.json").write_text(json.dumps(manifest["seed"]), encoding="utf-8")
                (work / "event.json").write_text(json.dumps(manifest["event"]), encoding="utf-8")
                env = {
                    **LOCAL_CREDENTIALS,
                    "DDB_ENDPOINT": "http://ddb:8000",
                    "S3_ENDPOINT": "http://minio:9000",
                    **manifest["environment"],
                }
                env_args = [part for k, v in env.items() for part in ("-e", f"{k}={v}")]

                def mount(src, dst):
                    return ("--mount", f"type=bind,src={src},dst={dst},readonly")

                python = ("--entrypoint", "/var/lang/bin/python3", "--read-only")
                self._launch(
                    containers,
                    prefix + "-ddb",
                    prefix,
                    images["ddb"],
                    ("-jar", "DynamoDBLocal.jar", "-inMemory", "-sharedDb"),
                    ("--network-alias", "ddb"),
                )
                self._launch(
                    containers,
                    prefix + "-minio",
                    prefix,
                    images["minio"],
                    ("server", "/data"),
                    (
                        "--network-alias",
                        "minio",
                        "--tmpfs",
                        "/data:size=64m",
                        "-e",
                        f"MINIO_ROOT_USER={LOCAL_CREDENTIALS['AWS_ACCESS_KEY_ID']}",
                        "-e",
                        f"MINIO_ROOT_PASSWORD={LOCAL_CREDENTIALS['AWS_SECRET_ACCESS_KEY']}",
                    ),
                )
                _, code = self._launch(
                    containers,
                    prefix + "-seed",
                    prefix,
                    images["lambda"],
                    ("/opt/seed.py",),
                    (
                        *python,
                        "--tmpfs",
                        "/tmp:size=32m",
                        *mount(HARNESS / "seed.py", "/opt/seed.py"),
                        *mount(work / "seed.json", "/opt/seed.json"),
                        *env_args,
                    ),
                    detach=False,
                )
                if code:
                    raise RuntimeFailure("local_services_seed_failed")
                checks.append("dynamodb_minio_seeded")
                self._launch(
                    containers,
                    prefix + "-candidate",
                    prefix,
                    images["lambda"],
                    (handler,),
                    (
                        "--network-alias",
                        "candidate",
                        "--read-only",
                        "--tmpfs",
                        "/tmp:size=64m",
                        "--user",
                        "1000:1000",
                        *mount(root, "/var/task"),
                        *env_args,
                    ),
                )
                budget = int(self.deadline - time.monotonic()) - 10
                if budget <= 5:
                    raise RuntimeFailure("timed_out")
                output, code = self._launch(
                    containers,
                    prefix + "-invoke",
                    prefix,
                    images["lambda"],
                    ("/opt/invoke.py", str(min(budget, 100))),
                    (
                        *python,
                        "--tmpfs",
                        "/tmp:size=16m",
                        *mount(HARNESS / "invoke.py", "/opt/invoke.py"),
                        *mount(work / "event.json", "/opt/event.json"),
                    ),
                    detach=False,
                )
                lines = [line for line in output.splitlines() if line.startswith(RESPONSE_MARKER)]
                if code or not lines:
                    raise RuntimeFailure("smoke_invocation_failed")
                if json.loads(lines[-1][len(RESPONSE_MARKER) :]) != manifest["expected"]:
                    raise RuntimeFailure("smoke_response_mismatch")
                checks.append("candidate_lambda_smoke_passed")
                if inspect_tree(source, self.settings.limits).content_hash != proposal.source_hash:
                    raise RuntimeFailure("source_changed_during_validation")
                status = "runtime_validated"
        except RuntimeFailure as error:
            errors.append(str(error))
            status = str(error) if str(error) in {"cancelled", "timed_out"} else "failed"
        except (OSError, ValueError, TypeError, KeyError, SyntaxError):
            errors.append("invalid_input_or_dependency_missing")
        finally:
            for name in reversed(containers):
                try:
                    output, code = self.command(
                        [docker, "rm", "--force", name], check=False, cleanup=True
                    )
                    if code and "no such container" not in output.lower():
                        errors.append("container_cleanup_failed")
                except (RuntimeFailure, OSError):
                    errors.append("container_cleanup_failed")
            if created_network:
                try:
                    self.command([docker, "network", "rm", prefix], cleanup=True)
                except (RuntimeFailure, OSError):
                    errors.append("network_cleanup_failed")
            if errors and status == "runtime_validated":
                status = "cleanup_failed"
        valid = status == "runtime_validated"
        gate = Governance().evaluate(
            action="openPR",
            tenant=tenant,
            owner=proposal.tenant,
            environment=environment,
            source_hash=proposal.source_hash,
            current_hash=proposal.source_hash if valid else "",
            proposal_id=proposal.proposal_id,
            validated=valid,
            runtime_validated=valid,
            access_safe=valid,
            approval=approval,
        )
        return {
            "status": status,
            "errors": errors,
            "checks": checks,
            "details": details,
            "images": images,
            "method": proposal.method,
            "source_hash": proposal.source_hash,
            "proposal_id": proposal.proposal_id,
            "candidate_hash": candidate_hash if valid else None,
            # Local emulators do not enforce IAM; only a real AWS deploy can verify it.
            "aws_iam_status": "not_verified",
            "pr_gate": gate.to_dict(),
            "audit": self.audit,
        }
