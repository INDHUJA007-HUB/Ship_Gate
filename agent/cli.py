from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from agent.cache import ScanCache, _finding
from agent.config import Settings
from agent.finding_policy import FindingPolicy, PolicyContext
from agent.governance import Approval, Governance
from agent.ingest import ingest
from agent.models import SCHEMA_VERSION, ScanReport
from agent.preflight import PreflightError
from agent.remediation import Proposal, propose_iam, validate_proposal
from agent.runtime_validation import validate_runtime
from agent.scan import ScanService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="first-commit")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser(
        "scan", help="statically scan an untrusted directory, .zip archive or https Git URL"
    )
    scan.add_argument("source", help="directory, .zip archive, or https Git URL")
    scan.add_argument("--cache-dir", type=Path, default=Path(".first-commit-cache"))
    scan.add_argument("--no-cache", action="store_true")
    propose = commands.add_parser("propose-iam", help="prepare a reviewable static IAM proposal")
    propose.add_argument("source", type=Path)
    propose.add_argument("target", help="relative path to a standalone JSON identity policy")
    propose.add_argument("--operations", required=True, type=Path)
    propose.add_argument("--tenant", required=True)
    propose.add_argument(
        "--environment", required=True, choices=["development", "staging", "production"]
    )
    propose.add_argument("--output", required=True, type=Path)
    validate = commands.add_parser("validate-proposal", help="read-only static validation")
    validate.add_argument("source", type=Path)
    validate.add_argument("proposal", type=Path)
    validate.add_argument("--tenant", required=True)
    validate.add_argument("--environment", required=True)
    validate.add_argument(
        "--approval",
        type=Path,
        help="trusted local operator approval; never supplied by scanned code",
    )
    commands.add_parser("validate-runtime", help="run packaged SAM smoke harness only")
    candidate = commands.add_parser(
        "validate-candidate", help="validate the actual patched Lambda locally"
    )
    candidate.add_argument("source", type=Path)
    candidate.add_argument("proposal", type=Path)
    candidate.add_argument("--tenant", required=True)
    candidate.add_argument("--environment", required=True)
    candidate.add_argument(
        "--manifest",
        required=True,
        type=Path,
        help="trusted validation manifest (event, expected response, seed) outside source",
    )
    candidate.add_argument("--approval", type=Path, help="trusted local operator approval")
    commands.add_parser("doctor", help="check installed project toolchain")
    policy = commands.add_parser(
        "policy", help="evaluate a saved normalized scan with embedded Cedar"
    )
    policy.add_argument("report", type=Path)
    policy.add_argument("--tenant", required=True)
    policy.add_argument("--user", required=True)
    policy.add_argument("--owner", required=True)
    policy.add_argument("--environment", action="append", default=[])
    policy.add_argument("--current-hash", required=True)
    policy.add_argument("--cache-db", type=Path, default=Path(".first-commit-cache/policy.sqlite3"))
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    if arguments.command == "policy":
        return _policy_command(arguments)
    if arguments.command != "scan":
        return _remediation_command(arguments)
    cache = None if arguments.no_cache else ScanCache(arguments.cache_dir)
    settings = Settings.from_env()
    try:
        # Archives and clones live in a temporary directory that is removed after the scan.
        with ingest(arguments.source, settings.limits) as source:
            report = ScanService(settings, cache=cache).scan(source.root, label=source.label)
    except PreflightError as error:
        print(json.dumps({"complete": False, "error": str(error)}, indent=2))
        return 2
    output = {**report.to_dict(), "ingestion": source.to_dict()}
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if report.complete else 2


def _load(path):
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("input document exceeds 1 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def _policy_command(args):
    try:
        data = _load(args.report)
        if data["schema_version"] != SCHEMA_VERSION:
            raise ValueError("Unsupported finding schema")
        report = ScanReport(
            data["schema_version"],
            data["source"],
            data["content_hash"],
            tuple(_finding(f) for f in data["findings"]),
            tuple(data["detector_errors"]),
        )
        result = FindingPolicy(args.cache_db).evaluate(
            report,
            PolicyContext(
                args.tenant, args.user, args.owner, tuple(args.environment), args.current_hash
            ),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return (
            0
            if result["status"] == "evaluated"
            and all(item["outcome"] != "deny" for item in result["decisions"])
            else 2
        )
    except (ValueError, TypeError, KeyError, OSError):
        print(json.dumps({"status": "error", "reason": "invalid_policy_input"}))
        return 2


def _remediation_command(args):
    try:
        if args.command == "doctor":
            import subprocess

            from agent.toolchain import command

            tools = {}
            for name in ("docker", "sam", "gitleaks", "semgrep", "checkov"):
                try:
                    result = subprocess.run(
                        [*command(name), "version" if name == "gitleaks" else "--version"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    tools[name] = {
                        "available": result.returncode == 0,
                        "version": result.stdout.strip(),
                    }
                except (OSError, subprocess.TimeoutExpired):
                    tools[name] = {"available": False}
            print(json.dumps(tools, indent=2))
            return 0 if all(t["available"] for t in tools.values()) else 2
        if args.command == "validate-candidate":
            from agent.candidate_runtime import CandidateRuntime

            if args.manifest.resolve().is_relative_to(args.source.resolve()):
                raise ValueError("a trusted validation manifest must be outside source")
            result = CandidateRuntime().validate(
                args.source,
                Proposal(**_load(args.proposal)),
                _load(args.manifest),
                tenant=args.tenant,
                environment=args.environment,
                approval=Approval(**_load(args.approval)) if args.approval else None,
            )
            print(json.dumps(result, indent=2))
            return 0 if result["status"] == "runtime_validated" else 2
        if args.command == "validate-runtime":
            result = validate_runtime()
            print(json.dumps(result.to_dict(), indent=2))
            return 0 if result.status == "passed" else 2
        if args.command == "propose-iam":
            if args.output.resolve().is_relative_to(args.source.resolve()):
                raise ValueError("proposal output must be outside source to preserve its hash")
            proposal = propose_iam(
                args.source,
                args.target,
                _load(args.operations),
                tenant=args.tenant,
                environment=args.environment,
            )
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(proposal.to_dict(), handle, indent=2)
            print(
                json.dumps(
                    {
                        "status": "proposed",
                        "proposal_id": proposal.proposal_id,
                        "method": proposal.method,
                    },
                    indent=2,
                )
            )
            return 0
        proposal = Proposal(**_load(args.proposal))
        validation = validate_proposal(
            args.source, proposal, tenant=args.tenant, environment=args.environment
        )
        approval = Approval(**_load(args.approval)) if args.approval else None
        engine = Governance()
        decision = engine.evaluate(
            action="openPR",
            tenant=args.tenant,
            owner=proposal.tenant,
            environment=args.environment,
            source_hash=proposal.source_hash,
            current_hash=proposal.source_hash if validation.status == "static_validated" else "",
            proposal_id=proposal.proposal_id,
            validated=validation.status == "static_validated",
            access_safe=validation.status == "static_validated",
            approval=approval,
            now=int(time.time()),
        )
        print(
            json.dumps(
                {"validation": validation.to_dict(), "pr_gate": decision.to_dict()}, indent=2
            )
        )
        return 0 if validation.status == "static_validated" else 2
    except (ValueError, OSError, TypeError, KeyError):
        print(
            json.dumps({"status": "failed", "error": "Invalid, unsupported, or inaccessible input"})
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
