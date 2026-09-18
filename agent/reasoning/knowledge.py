"""Trusted, versioned security knowledge: per-category playbooks and the policy glossary.

The same playbooks feed the prompts (only for categories present), validate model advice
(required steps and forbidden advice), and render zero-cost deterministic explanations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

AUDIENCES = ("beginner", "developer")
# Generic file names advice may mention without appearing in scan evidence.
KNOWN_FILES = frozenset({".env.example", ".env", ".gitignore"})
# Well-known variable names explanations may mention without appearing in scan evidence.
KNOWN_VARIABLES = frozenset(
    {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION"}
)


@dataclass(frozen=True)
class Playbook:
    category: str
    label: str
    impact: str
    cwe: str
    guidance: str  # Prompt module: what a correct, safe explanation must cover.
    what: str
    why: str
    fix: tuple[str, ...]
    verify: tuple[str, ...]
    uncertainty: tuple[str, ...]
    must_mention: str  # Regex that the fix steps must match.
    deterministic_ok: bool = False  # A template fully explains a low-difficulty instance.


PLAYBOOKS = {
    "secret": Playbook(
        category="secret",
        label="Hardcoded secret",
        impact="credential_exposure",
        cwe="CWE-798",
        guidance=(
            "Secrets: the first fix step is always to revoke or rotate the credential with its "
            "provider, because deleting it from code does not remove it from Git history, forks "
            "or build logs. Then load it at runtime from a secret store or environment variable, "
            "and check the provider's logs for misuse. Never repeat the value."
        ),
        what=(
            "The {detector} rule {rule} matched what looks like a credential at {where}. "
            "The value is not shown here."
        ),
        why=(
            "Anyone who can read this repository, its history or a build log can use the "
            "credential as if they were your application. Deleting the line does not remove it "
            "from Git history."
        ),
        fix=(
            "Revoke or rotate this credential with its provider now, before changing any code.",
            "Remove it from the code and load it at runtime from a secret store such as AWS SSM "
            "Parameter Store, or from an environment variable.",
            "Review the provider's access logs for any use of the old credential.",
        ),
        verify=(
            "Confirm the provider rejects the old credential.",
            "Run the scan again and confirm this location no longer reports a secret.",
        ),
        uncertainty=(
            "The scanner matched a pattern; it cannot tell whether the credential is still active.",
        ),
        must_mention=r"rotat|revok|invalidat|deactivat",
    ),
    "iam_wildcard": Playbook(
        category="iam_wildcard",
        label="Over-permissive IAM policy",
        impact="privilege_escalation",
        cwe="CWE-269",
        guidance=(
            "IAM: explain least privilege in plain words. The evidence lists failed check IDs but "
            "not the policy's actions, so never name specific AWS actions or ARNs. Tell the reader "
            "to list the operations their code performs and grant only those on specific "
            "resources, and to generate the reviewed proposal with first-commit propose-iam so "
            "the no-expansion proof and local validation run."
        ),
        what=(
            "Checkov checks {checks} failed for {resources} in {where}: the policy grants actions "
            "or resources without constraints."
        ),
        why=(
            "If this role's code or credentials are misused, the broad grant lets an attacker "
            "reach far more than the application needs, potentially every matching resource in "
            "the account."
        ),
        fix=(
            "List the specific operations the application's code performs with this role.",
            "Replace the broad grant with only those actions, scoped to the specific resources "
            "they touch (least privilege).",
            "Generate the change with first-commit propose-iam so the no-expansion proof and "
            "local validation run before any pull request.",
        ),
        verify=(
            "Run the scan again and confirm these Checkov IAM checks pass.",
            "Exercise the application's normal paths and confirm no access-denied errors.",
        ),
        uncertainty=(
            "The evidence does not show which AWS actions the application actually needs.",
        ),
        must_mention=r"least[- ]privilege|specific|only (the|those)|narrow|scop",
    ),
    "missing_auth": Playbook(
        category="missing_auth",
        label="Route without an authorization check",
        impact="unauthorized_access",
        cwe="CWE-862",
        guidance=(
            "Authorization: distinguish authentication (who is calling) from authorization "
            "(whether they may act on this data). The detector is a heuristic that cannot see "
            "middleware or API gateway protection, so tell the reader what to check rather than "
            "asserting the route is exposed."
        ),
        what=(
            "The route handler at {where} does not call any authorization check that First "
            "Commit recognizes, such as a login-required decorator or a current-user check."
        ),
        why=(
            "If nothing else protects this route, anyone who can reach the URL can call it "
            "without signing in, and may read or change data that is not theirs."
        ),
        fix=(
            "Decide who is allowed to call this route and what data they may touch.",
            "Add your framework's authentication check before the handler runs, for example a "
            "login-required decorator.",
            "Inside the handler, check that the signed-in user is authorized for the specific "
            "record, not just logged in.",
        ),
        verify=(
            "Call the route without credentials and confirm it returns 401 or 403.",
            "Call it as a different user and confirm they cannot reach another user's data.",
        ),
        uncertainty=("The detector cannot see protection added by middleware or an API gateway.",),
        must_mention=r"authenticat|authoriz|log(ged)?[- ]?in|sign(ed)?[- ]in|access check",
    ),
    "missing_input_validation": Playbook(
        category="missing_input_validation",
        label="Request input used without validation",
        impact="data_exposure",
        cwe="CWE-20",
        guidance=(
            "Validation: explain that request data is attacker-controlled and must be checked "
            "against an explicit schema (types, required fields, lengths, allowed values) before "
            "use, rejecting invalid input with a 400. Recommend the framework's schema library "
            "rather than hand-written checks."
        ),
        what=(
            "The route at {where} reads request data without a validation step First Commit "
            "recognizes, such as a schema load or model validation."
        ),
        why=(
            "Request data comes from whoever calls the route. Unchecked values can crash the "
            "handler, store corrupted data, or reach queries and files in unsafe forms."
        ),
        fix=(
            "Define a schema for the request body: required fields, types, lengths and allowed "
            "values.",
            "Validate the input against that schema before using it, and reject invalid input "
            "with a 400 response.",
            "Use only the validated values in the rest of the handler.",
        ),
        verify=(
            "Send a request with a missing or wrong-typed field and confirm it is rejected with "
            "a 400.",
        ),
        uncertainty=("The detector cannot see validation performed in a separate helper.",),
        must_mention=r"validat|schema|allow[- ]?list|reject",
    ),
    "missing_environment_variable": Playbook(
        category="missing_environment_variable",
        label="Undeclared required environment variable",
        impact="runtime_failure",
        cwe="",
        guidance=(
            "Environment: this is a deterministic fact, not a guess. The code reads a variable "
            "that no template or .env.example declares, so the app will crash at startup where "
            "it is missing. Tell the reader to declare it and to keep any secret value in a "
            "secret store."
        ),
        what=(
            "The code at {where} requires {variables}, but no template or .env.example in the "
            "repository declares it."
        ),
        why=(
            "When the application starts somewhere this variable is not set, such as a fresh "
            "deploy, it fails immediately with a missing-key error."
        ),
        fix=(
            "Declare {variables} in the deployment template's environment variables, or document "
            "it in .env.example.",
            "If the value is a secret, store it in a secret store such as SSM Parameter Store and "
            "reference it instead of writing the value.",
        ),
        verify=("Run the scan again and confirm this variable is reported as declared.",),
        uncertainty=(),
        must_mention=r"declar|template|\.env\.example|document",
        deterministic_ok=True,
    ),
    "unsafe_command_execution": Playbook(
        category="unsafe_command_execution",
        label="Unsafe command execution",
        impact="unsafe_code_execution",
        cwe="CWE-78",
        guidance=(
            "Command execution: shell=True lets shell syntax in any input run as commands. "
            "Recommend passing an argument list with shell=False and validating any value that "
            "reaches the command against an allow-list. A plain subprocess call is lower risk "
            "but still needs its inputs reviewed."
        ),
        what="The {detector} rule {rule} matched a subprocess call at {where}.",
        why=(
            "If any part of the command comes from users or external data, an attacker may be "
            "able to run their own commands on the server."
        ),
        fix=(
            "Pass the command as a list of arguments with shell=False instead of a single string.",
            "Validate any value that reaches the command against an allow-list of expected values.",
        ),
        verify=(
            "Pass input containing shell characters such as ; and confirm it is not executed.",
        ),
        uncertainty=("The evidence does not show where the command's inputs come from.",),
        must_mention=r"shell\s*=\s*False|argument(s)? list|list of arguments|allow[- ]?list",
    ),
}

REASONS = {
    "missing-or-invalid-context": (
        "The scan context was missing, stale, from another tenant, or the scan was incomplete."
    ),
    "secret-requires-review": "Secrets always need a person to confirm rotation and removal.",
    "iam-requires-review": "Any change to IAM permissions needs human review.",
    "auth-requires-review": "Authorization findings always need human review.",
    "high-risk-requires-review": "High and critical severity findings need human review.",
    "eligible-static-processing": (
        "A deterministic fact in a low-risk category may be processed automatically."
    ),
    "production-or-conflicting-environment": (
        "Production, or conflicting environment tags, always requires review."
    ),
    "compound-risk": "Several findings affect the same file or resource.",
    "batch-summary-required": "There are too many findings to process one by one.",
    "known-example-in-documentation": (
        "The secret matched a published example value in documentation or tests."
    ),
    "review-supported-finding": "The finding is eligible for human review.",
    "command-execution-requires-review": "Command execution findings always need human review.",
}
# Vetted definitions for common concept questions: answered with no model call.
CONCEPTS = {
    "least privilege": (
        "Least privilege means giving code or people only the permissions they need, on the "
        "specific resources they use, and nothing more. If that code is ever misused, the damage "
        "is limited to what it was allowed to do.",
        ("iam_wildcard",),
    ),
    "iam": (
        "IAM (Identity and Access Management) is how AWS decides who or what may perform which "
        "actions on which resources. Policies attached to roles grant those permissions.",
        ("iam_wildcard",),
    ),
    "wildcard": (
        "A wildcard in an IAM policy grants every action or resource that matches it, which is "
        "usually far more access than an application needs.",
        ("iam_wildcard",),
    ),
    "cedar": (
        "Cedar is the policy language First Commit uses to decide how each finding is handled: "
        "processed automatically, sent to a person for review, or denied. Its decisions come from "
        "versioned rules, not from a model.",
        (),
    ),
    "authentication": (
        "Authentication checks who is calling, for example by requiring a signed-in session or a "
        "valid token.",
        ("missing_auth",),
    ),
    "authorization": (
        "Authorization checks whether the caller may perform this action on this specific data. "
        "A route can require sign-in and still let one user reach another user's records.",
        ("missing_auth",),
    ),
    "input validation": (
        "Input validation checks request data against explicit rules, such as required fields, "
        "types, lengths and allowed values, and rejects anything else before the code uses it.",
        ("missing_input_validation",),
    ),
    "command injection": (
        "Command injection happens when untrusted input becomes part of a shell command, letting "
        "an attacker run their own commands. Passing an argument list without a shell prevents it.",
        ("unsafe_command_execution",),
    ),
    "sql injection": (
        "SQL injection happens when untrusted input becomes part of a database query. "
        "Parameterized queries keep input as data and prevent it.",
        (),
    ),
    "environment variable": (
        "Environment variables pass configuration, such as service endpoints or references to "
        "secrets, to an application when it starts, instead of writing values into code.",
        ("missing_environment_variable",),
    ),
    "hardcoded secret": (
        "A hardcoded secret is a credential written directly into code or configuration. Anyone "
        "who can read the repository or its history can use it, so it must be rotated and moved "
        "to a secret store.",
        ("secret",),
    ),
    "prompt injection": (
        "Prompt injection is text that tries to give an AI model new instructions. First Commit "
        "treats repository text and questions as data, so such text cannot change its rules or "
        "its policy decisions.",
        (),
    ),
    "gitleaks": ("Gitleaks is an open-source scanner that finds credentials in code.", ("secret",)),
    "semgrep": (
        "Semgrep is an open-source static analysis tool that matches risky code patterns, such as "
        "running commands through a shell.",
        ("unsafe_command_execution",),
    ),
    "checkov": (
        "Checkov is an open-source scanner for infrastructure templates; here it flags IAM "
        "policies that grant unconstrained access.",
        ("iam_wildcard",),
    ),
}
CONCEPT_ALIASES = {
    "least-privilege": "least privilege",
    "authorisation": "authorization",
    "shell injection": "command injection",
    "secret scanning": "hardcoded secret",
    "wildcards": "wildcard",
    "environment variables": "environment variable",
    "hardcoded secrets": "hardcoded secret",
    "a hardcoded secret": "hardcoded secret",
}


def concept_entry(term: str | None):
    if not term:
        return None
    key = " ".join(term.lower().split())
    key = CONCEPT_ALIASES.get(key, key)
    return (key, *CONCEPTS[key]) if key in CONCEPTS else None


DECISIONS = {
    "permit": "eligible for automated processing (never an approval to deploy)",
    "needs_human_approval": "needs a person to review it",
    "deny": "blocked from processing",
}


def version() -> str:
    material = {
        "playbooks": {key: asdict(value) for key, value in PLAYBOOKS.items()},
        "concepts": CONCEPTS,
        "reasons": REASONS,
        "decisions": DECISIONS,
        "files": sorted(KNOWN_FILES),
        "variables": sorted(KNOWN_VARIABLES),
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()[:16]


KNOWLEDGE_VERSION = version()


def where(group) -> str:
    first = group.locations[0]
    text = f"{first.path} line {first.line}" if first.line else first.path
    others = group.count - 1
    if others:
        text += f" and {others} other place{'s' if others > 1 else ''}"
    return text


def template_explanation(group) -> dict:
    """Deterministic, grounded explanation rendered only from trusted text and scan facts."""
    playbook = PLAYBOOKS[group.category]
    details = group.details
    values = {
        "where": where(group),
        "detector": group.detector,
        "rule": group.rule,
        "checks": ", ".join(details.get("checks", [])) or "for IAM",
        "resources": ", ".join(details.get("resources", [])) or "this role",
        "variables": ", ".join(details.get("environment_variables", [])) or "a variable",
    }
    what = playbook.what.format(**values)
    fix = [step.format(**values) for step in playbook.fix]
    if group.category == "unsafe_command_execution" and group.rule.endswith("unsafe-shell"):
        what += " It runs the command through a shell (shell=True)."
    suppressed = details.get("inline_suppressed_checks")
    if suppressed:
        what += (
            f" The repository marks {', '.join(suppressed)} as skipped inline; that suppression "
            "was ignored because scanned code cannot silence First Commit."
        )
    location_refs = [location.ref for location in group.locations[:3]]
    return {
        "headline": f"{playbook.label} at {where(group)}"[:140],
        "what_happened": what,
        "why_it_matters": playbook.why,
        "impact": playbook.impact,
        "fix_steps": [{"action": step, "refs": [group.id, *location_refs]} for step in fix],
        "verify": list(playbook.verify),
        "uncertainty": list(playbook.uncertainty)
        if group.evidence_class != "deterministic_fact"
        else [],
        "refs": [group.id, f"{group.id}.decision", *location_refs],
        "escalation": "none",
    }


def reason_text(reason_id: str) -> str:
    return REASONS.get(reason_id, "A versioned policy rule applied.")
