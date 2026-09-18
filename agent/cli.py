from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from agent.cache import ScanCache, report_from_dict
from agent.config import Settings
from agent.finding_policy import FindingPolicy, PolicyContext
from agent.governance import Approval, Governance
from agent.ingest import ingest
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
    for name, description in (
        ("explain", "explain policy-evaluated findings in plain language (Phase 5)"),
        ("ask", "answer a question about a policy-evaluated scan (Phase 5)"),
    ):
        reasoning = commands.add_parser(name, help=description)
        reasoning.add_argument("report", type=Path, help="JSON from first-commit scan")
        reasoning.add_argument("policy_result", type=Path, help="JSON from first-commit policy")
        if name == "ask":
            reasoning.add_argument("question")
        reasoning.add_argument("--tenant", required=True)
        reasoning.add_argument("--user", required=True)
        reasoning.add_argument("--audience", choices=["beginner", "developer"], default="beginner")
        reasoning.add_argument(
            "--provider",
            choices=["none", "anthropic", "bedrock", "ollama"],
            help="model provider (default: FIRST_COMMIT_MODEL_PROVIDER, else none)",
        )
        reasoning.add_argument("--region", help="AWS region for the bedrock provider")
        reasoning.add_argument("--small-model", help="explicit low-level model name")
        reasoning.add_argument("--large-model", help="explicit high-level model name")
        reasoning.add_argument(
            "--ollama-profile",
            choices=["qwen3", "deepseek-r1", "mistral", "olmo2", "gpt-oss", "kimi"],
            help="reviewed local small/large model pair",
        )
        reasoning.add_argument("--ollama-url", help="loopback Ollama URL")
        reasoning.add_argument("--ollama-max-context", type=int, help="local context safety cap")
        reasoning.add_argument("--ollama-timeout", type=float, help="local inference timeout")
        reasoning.add_argument("--max-calls", type=int, default=12)
        reasoning.add_argument("--max-cost", type=float, default=1.0, help="USD, list price")
        reasoning.add_argument(
            "--cache-db", type=Path, default=Path(".first-commit-cache/explanations.sqlite3")
        )
        reasoning.add_argument("--refresh", action="store_true", help="ignore cached results")
    remediate = commands.add_parser(
        "remediate-iam",
        help="propose a strictly narrower policy from activity or a labelled estimate (Phase 7)",
    )
    remediate.add_argument("source", type=Path)
    remediate.add_argument("target", help="relative path to a JSON or SAM YAML identity policy")
    remediate.add_argument("--tenant", required=True)
    remediate.add_argument(
        "--environment", required=True, choices=["development", "staging", "production"]
    )
    remediate.add_argument(
        "--role", help="IAM role ARN whose activity should be analyzed (activity method only)"
    )
    remediate.add_argument(
        "--method",
        choices=["auto", "activity", "static"],
        default="auto",
        help="auto prefers real activity and states when it falls back to an estimate",
    )
    remediate.add_argument("--trail-arn", help="CloudTrail trail ARN to analyze")
    remediate.add_argument(
        "--access-role", help="service role IAM Access Analyzer assumes to read the trail"
    )
    remediate.add_argument("--start-time", help="ISO-8601 start of the activity window")
    remediate.add_argument("--end-time", help="ISO-8601 end of the activity window")
    remediate.add_argument("--regions", help="comma-separated regions covered by the trail")
    remediate.add_argument("--all-regions", action="store_true")
    remediate.add_argument("--region", help="AWS region for the Access Analyzer client")
    remediate.add_argument(
        "--verify",
        choices=["local", "aws"],
        default="local",
        help="local subset proof, plus CheckNoNewAccess when aws is reachable",
    )
    remediate.add_argument("--timeout", type=float, default=600, help="generation timeout, seconds")
    remediate.add_argument("--interval", type=float, default=5, help="poll interval, seconds")
    remediate.add_argument(
        "--json", action="store_true", help="print the full recommendation instead of the report"
    )
    remediate.add_argument("--output", type=Path, help="also write the recommendation JSON here")
    _pipeline_parsers(commands)
    return parser


def _pipeline_parsers(commands) -> None:
    def principal(command, user=True):
        command.add_argument("--tenant", required=True)
        if user:
            command.add_argument("--user", required=True)
        command.add_argument(
            "--state-dir", type=Path, default=Path(".first-commit-cache"), help="local state root"
        )

    def faults(command):
        command.add_argument(
            "--fault",
            action="append",
            default=[],
            metavar="STEP=KIND[:N]",
            help="operator-only chaos testing, e.g. semgrep=timeout or gitleaks=transient:2",
        )

    run = commands.add_parser("run", help="run the durable scan pipeline (Phase 6)")
    run.add_argument("source", help="directory, .zip archive, or https Git URL")
    principal(run)
    run.add_argument(
        "--environment",
        action="append",
        default=[],
        choices=["development", "staging", "production"],
    )
    run.add_argument("--audience", choices=["beginner", "developer"], default="beginner")
    run.add_argument("--provider", choices=["none", "anthropic", "bedrock", "ollama"])
    run.add_argument("--region")
    run.add_argument("--idempotency-key", help="the same key always names the same run")
    run.add_argument("--refresh", action="store_true", help="do not reuse an identical result")
    run.add_argument("--no-external", action="store_true", help="first-party detectors only")
    run.add_argument("--trace", action="store_true", help="include the state transition history")
    faults(run)
    resume = commands.add_parser("resume", help="rerun only the incomplete checks of a run")
    resume.add_argument("run_id")
    principal(resume)
    resume.add_argument("--provider", choices=["none", "anthropic", "bedrock", "ollama"])
    resume.add_argument("--no-external", action="store_true")
    resume.add_argument("--trace", action="store_true")
    faults(resume)
    status = commands.add_parser("runs", help="show a run's status, or its full result")
    status.add_argument("run_id")
    principal(status, user=False)
    status.add_argument("--result", action="store_true")
    reviews = commands.add_parser("reviews", help="list review items (the dead-letter path)")
    principal(reviews, user=False)
    reviews.add_argument("--run")
    orchestrate = commands.add_parser(
        "orchestrate", help="send a request to the orchestrating agent"
    )
    orchestrate.add_argument("request")
    principal(orchestrate)
    orchestrate.add_argument(
        "--model",
        choices=["none", "anthropic", "bedrock"],
        default="none",
        help="model for requests the deterministic planner cannot map (default: none)",
    )
    orchestrate.add_argument("--region")
    orchestrate.add_argument("--no-external", action="store_true")


def main() -> int:
    arguments = build_parser().parse_args()
    if arguments.command in {"run", "resume", "runs", "reviews", "orchestrate"}:
        return _pipeline_command(arguments)
    if arguments.command == "policy":
        return _policy_command(arguments)
    if arguments.command in {"explain", "ask"}:
        return _reasoning_command(arguments)
    if arguments.command == "remediate-iam":
        return _least_privilege_command(arguments)
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


def _reasoning_command(args):
    from agent.reasoning import ReasoningConfig, ReasoningContext, ReasoningService
    from agent.reasoning.budget import Budget
    from agent.reasoning.cache import SqliteExplanationCache
    from agent.reasoning.providers import ProviderError, build_provider

    try:
        report = report_from_dict(_load(args.report))
        policy = _load(args.policy_result)
        service = ReasoningService(
            build_provider(
                args.provider,
                region=args.region,
                small_model=args.small_model,
                large_model=args.large_model,
                ollama_profile=args.ollama_profile,
                ollama_url=args.ollama_url,
                ollama_max_context=args.ollama_max_context,
                ollama_timeout=args.ollama_timeout,
            ),
            SqliteExplanationCache(args.cache_db),
            ReasoningConfig(budget=Budget(max_calls=args.max_calls, max_cost_usd=args.max_cost)),
        )
        context = ReasoningContext(args.tenant, args.user, args.audience, args.refresh)
        if args.command == "explain":
            result = service.explain(report, policy, context)
            passed = result["status"] == "complete"
        else:
            result = service.ask(args.question, report, policy, context)
            passed = result["status"] in {"answered", "blocked", "clarification_needed"}
    except ProviderError as error:
        print(json.dumps({"status": "error", "reason": f"provider_{error.kind}"}))
        return 2
    except (ValueError, TypeError, KeyError, OSError):
        print(json.dumps({"status": "error", "reason": "invalid_reasoning_input"}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if passed else 2


EXIT_CODES = {"completed": 0, "failed": 2, "partial": 3}


def _pipeline_command(args):
    from agent.orchestration.contracts import InvalidRequest, new_run_id
    from agent.orchestration.faults import FaultPlan
    from agent.orchestration.pipeline import STEP_NAMES, local_pipeline
    from agent.reasoning.providers import ProviderError, build_provider

    provider = getattr(args, "provider", None)
    region = getattr(args, "region", None)
    try:
        pipeline = local_pipeline(
            args.state_dir,
            faults=FaultPlan.parse(getattr(args, "fault", []), STEP_NAMES),
            external_detectors=not getattr(args, "no_external", False),
            provider_factory=lambda: build_provider(provider, region=region),
            provider_identity=provider or "env",
        )
        tenant = args.tenant
        if args.command == "reviews":
            print(json.dumps(pipeline.reviews(tenant, args.run), indent=2, sort_keys=True))
            return 0
        if args.command == "runs":
            run = pipeline.status(tenant, args.run_id)
            shown = pipeline.result(tenant, args.run_id) if args.result else run
            if shown is None:
                print(json.dumps({"status": "error", "reason": "run_not_found"}))
                return 2
            print(json.dumps(shown, indent=2, sort_keys=True))
            return EXIT_CODES.get(run["status"], 0)
        if args.command == "orchestrate":
            from agent.orchestration.agent import OrchestratorAgent

            model = None
            if args.model != "none":
                from agent.orchestration.claude_model import ClaudeModel

                model = ClaudeModel(args.model, region=region)
            agent = OrchestratorAgent(
                pipeline,
                tenant=tenant,
                user=args.user,
                explanations=pipeline.context.explanations,
                provider_factory=lambda: build_provider(None),
                model=model,
            )
            reply = agent.handle(args.request)
            print(json.dumps(reply, indent=2, sort_keys=True))
            return 0 if reply["route"] not in {"rejected", "model_error"} else 2
        if args.command == "resume":
            run = pipeline.resume(tenant, args.run_id)
        else:
            run = pipeline.submit(
                {
                    "tenant_id": tenant,
                    "user_id": args.user,
                    "run_id": new_run_id(tenant, args.idempotency_key),
                    "source_ref": args.source,
                    "environments": args.environment,
                    "audience": args.audience,
                    "refresh": args.refresh,
                }
            )
    except (InvalidRequest, ProviderError, ValueError) as error:
        reason = str(error) if isinstance(error, InvalidRequest) else "invalid_pipeline_input"
        print(json.dumps({"status": "error", "reason": reason}))
        return 2
    output = pipeline.result(tenant, run["run_id"]) or run
    if getattr(args, "trace", False) and pipeline.last_execution:
        output = {**output, "trace": pipeline.last_execution.history}
    print(json.dumps(output, indent=2, sort_keys=True))
    return EXIT_CODES.get(run["status"], 2)


def _least_privilege_command(args):
    from agent.least_privilege import recommend, render

    generator = None
    if (args.role and args.method != "static") or args.verify == "aws":
        try:
            from agent.access_analyzer import build_analyzer

            generator = build_analyzer(args.region)
        except Exception:  # noqa: BLE001 - reported as a missing-analyzer reason code
            generator = None
    if args.verify == "aws" and generator is None:
        print(json.dumps({"status": "failed", "error": "aws_verification_requires_credentials"}))
        return 2
    try:
        cloud_trail = None
        if args.trail_arn:
            from agent.access_analyzer import cloud_trail_from_config

            cloud_trail = cloud_trail_from_config(
                trail_arn=args.trail_arn,
                access_role=args.access_role,
                start_time=args.start_time,
                end_time=args.end_time,
                regions=[item for item in (args.regions or "").split(",") if item],
                all_regions=args.all_regions,
            )
        elif args.access_role or args.start_time or args.end_time:
            raise ValueError("incomplete_cloud_trail_details")
        recommendation = recommend(
            args.source,
            args.target,
            tenant=args.tenant,
            environment=args.environment,
            role_arn=args.role,
            method=args.method,
            generator=generator,
            cloud_trail=cloud_trail,
            verify=args.verify,
            timeout_seconds=args.timeout,
            interval_seconds=args.interval,
        )
    except (ValueError, OSError, TypeError, KeyError):
        print(
            json.dumps({"status": "failed", "error": "Invalid, unsupported, or inaccessible input"})
        )
        return 2
    payload = recommendation.to_dict()
    if args.output:
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
    print(json.dumps(payload, indent=2, sort_keys=True) if args.json else render(recommendation))
    return 0 if recommendation.chosen else 2


def _policy_command(args):
    try:
        report = report_from_dict(_load(args.report))
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
