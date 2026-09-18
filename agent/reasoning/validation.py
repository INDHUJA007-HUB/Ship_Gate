"""Semantic validation: model output must be grounded in the evidence packet.

Schema validity is necessary but not sufficient. These checks catch hallucinated references,
paths, lines, check IDs, AWS actions and variables; secret material; claims that override the
policy ("safe to deploy", "false positive"); unsafe advice; and missing essential fix steps.
Violation codes are stable and double as the corrective-retry instructions.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from agent.reasoning.evidence import SECRET_PATTERNS, EvidencePacket, Group
from agent.reasoning.knowledge import KNOWN_FILES, KNOWN_VARIABLES, PLAYBOOKS
from agent.reasoning.schemas import (
    ANSWER,
    CLASSIFICATION,
    EXPLANATION,
    MAX_BATCH,
    SYNTHESIS,
    validate,
)

SYNTHESIS_ID = "SYNTHESIS"

REF_TOKEN = re.compile(r"\b(?:SCAN|G[1-9][0-9]{0,2})(?:\.[A-Za-z][A-Za-z0-9_]*){0,2}\b")
GROUP_TOKEN = re.compile(r"\bG[1-9][0-9]{0,2}\b")
PATH_WITH_DIR = re.compile(r"(?<![\w@:/.-])((?:[\w.-]+/)+[\w.-]*\.[A-Za-z0-9]{1,10})\b")
BARE_FILE = re.compile(
    r"(?<![\w@:/.-])([\w-]+\.(?:py|yaml|yml|toml|tf|js|jsx|ts|tsx|go|rb|java|php|cs|sh))\b", re.I
)
LINE_TOKEN = re.compile(r"\blines?\s+(\d{1,6})\b", re.I)
PATH_LINE = re.compile(r"\.[A-Za-z0-9]{1,10}:(\d{1,6})\b")
CHECK_TOKEN = re.compile(r"\bCKV2?_[A-Z0-9_]+\b")
CWE_TOKEN = re.compile(r"\bCWE-\d{1,5}\b")
AWS_ACTION = re.compile(r"\b[a-z][a-z0-9-]{1,30}:(?:\*|[A-Z][A-Za-z0-9]*\*?)")
ARN_TOKEN = re.compile(r"\barn:aws[a-z-]*:", re.I)
VARIABLE_TOKEN = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")
HIGH_ENTROPY = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
INJECTION_ECHO = re.compile(
    r"(?i)ignore (all |any )?(previous|prior|above) instructions|system prompt|you are now|"
    r"developer mode|</?\s*system\s*>"
)
HYPOTHETICAL = re.compile(
    r"(?i)\b(not|never|no|isn't|aren't|wasn't|cannot|can't|don't|doesn't|won't|shouldn't|"
    r"if|whether|unless|until|even|believe|think|suspect|might|may be|could be|claim)\b"
)
AUTHORITY_CLAIMS = (
    re.compile(
        r"(?i)\b(safe|okay|ok|fine|ready)\s+to\s+(deploy|ship|merge|release|ignore|go live)\b"
    ),
    re.compile(
        r"(?i)\b(is|are|was|looks like|likely|probably|seems to be|appears to be)\s+"
        r"(an?\s+)?(harmless\s+)?false[\s-]+positives?\b"
    ),
    re.compile(
        r"(?i)\bno\s+(action|fix|change|remediation)s?\s+(is\s+|are\s+)?(needed|required|necessary)\b"
    ),
    re.compile(
        r"(?i)\b(can|may|could)\s+(safely\s+)?(ignore|dismiss|skip)\s+(this|these|the|that|those|it)"
        r"\s*(finding|warning|issue|alert|result|review|check)?s?\b"
    ),
    re.compile(r"(?i)\b(has|have)\s+been\s+(approved|resolved|remediated)\b"),
    re.compile(r"(?i)\bmark(ed)?\s+(it|this|them)?\s*(as\s+)?(safe|resolved|approved)\b"),
    re.compile(
        r"(?i)\bpolicy\s+(allows|permits|approved|approves)\s+(deploy|deployment|this change)\b"
    ),
)
# Claims that assert the finding is not real; a negation is part of the claim itself.
DISMISSALS = (
    re.compile(
        r"(?i)\b(not|isn't|is not)\s+(a\s+)?(real|actual|genuine|true)\s+(issue|problem|risk|"
        r"vulnerability|finding)\b"
    ),
    re.compile(r"(?i)\bnothing to (fix|worry about)\b"),
)
LOW_RISK = re.compile(r"(?i)\b(risk|impact|danger)\s+is\s+(low|minimal|negligible|none)\b")
ADVICE_NEGATION = re.compile(
    r"(?i)\b(avoid|never|not|don't|do not|instead of|rather than|remove|removing|replace|"
    r"replacing|stop|without|drop|delete|narrow|eliminate|no longer|disallow)\b"
)
UNSAFE_ADVICE = (
    (re.compile(r"shell\s*=\s*True"), "recommends shell=True"),
    (
        re.compile(r"(?i)[\"']\*[\"']|\b(Action|Resource)\s*[:=]\s*[\"']?\*|(?<=\w):\*"),
        "recommends wildcard permissions",
    ),
    (
        re.compile(
            r"(?i)\bdisabl\w*\s+(the\s+)?(auth\w*|validation|scann\w*|checkov|semgrep|gitleaks|"
            r"tls|ssl|certificate|csrf|verification)"
        ),
        "recommends disabling a protection",
    ),
    (
        re.compile(r"(?i)gitleaks:allow|nosemgrep|checkov:skip|#\s*nosec|--no-verify"),
        "recommends suppressing a scanner",
    ),
    (
        re.compile(
            r"(?i)\b(hard-?code|commit|embed|paste)\w*\s+(the\s+|a\s+|your\s+)?(new\s+)?"
            r"(secret|key|credential|token|password)s?\s+(in|into)\s+(the\s+)?(code|repo|repository|source)"
        ),
        "recommends hardcoding secrets",
    ),
    (re.compile(r"\bverify\s*=\s*False\b"), "recommends disabling TLS verification"),
)


@dataclass(frozen=True)
class Violation:
    code: str
    target: str
    detail: str

    def to_dict(self) -> dict:
        return {"code": self.code, "target": self.target, "detail": self.detail}


@dataclass
class BatchCheck:
    accepted: dict[str, dict] = field(default_factory=dict)
    violations: dict[str, list[Violation]] = field(default_factory=lambda: defaultdict(list))
    batch_violations: list[Violation] = field(default_factory=list)


def _sentences(text: str) -> list[str]:
    return [part for part in re.split(r"(?<=[.!?;])\s+|\n+", text) if part.strip()]


def _short(value: str, limit: int = 60) -> str:
    return re.sub(r"\s+", " ", value)[:limit]


def _prose(*values) -> list[str]:
    out = []
    for value in values:
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, list):
            out.extend(_prose(*value))
        elif isinstance(value, dict):
            out.extend(
                _prose(*(v for k, v in value.items() if k not in {"refs", "group_id", "group_ids"}))
            )
    return out


@dataclass(frozen=True)
class Grounding:
    groups: tuple[Group, ...]
    packet: EvidencePacket

    @property
    def paths(self) -> set[str]:
        paths = {loc.path for g in self.groups for loc in g.locations}
        return paths | {p.rsplit("/", 1)[-1] for p in paths} | set(KNOWN_FILES)

    @property
    def lines(self) -> set[int]:
        return {loc.line for g in self.groups for loc in g.locations if loc.line}

    @property
    def checks(self) -> set[str]:
        return {
            check
            for g in self.groups
            for key in ("checks", "inline_suppressed_checks")
            for check in g.details.get(key, [])
        }

    @property
    def variables(self) -> set[str]:
        found = {v for g in self.groups for v in g.details.get("environment_variables", [])}
        return found | set(KNOWN_VARIABLES)

    @property
    def cwes(self) -> set[str]:
        return {PLAYBOOKS[g.category].cwe for g in self.groups if PLAYBOOKS[g.category].cwe}

    @property
    def refs(self) -> set[str]:
        return {ref for g in self.groups for ref in g.refs()} | set(self.packet.scan_refs())


def _identifiers(text: str, grounding: Grounding, target: str) -> list[Violation]:
    violations = []
    without_refs = REF_TOKEN.sub(" ", text)
    for match in PATH_WITH_DIR.finditer(without_refs):
        if (
            match.group(1).strip("./") not in grounding.paths
            and match.group(1) not in grounding.paths
        ):
            violations.append(
                Violation(
                    "UNGROUNDED_PATH",
                    target,
                    f"path {_short(match.group(1))!r} is not in the evidence",
                )
            )
    for match in BARE_FILE.finditer(without_refs):
        if match.group(1) not in grounding.paths:
            violations.append(
                Violation(
                    "UNGROUNDED_PATH",
                    target,
                    f"file {_short(match.group(1))!r} is not in the evidence",
                )
            )
    lines = {int(m.group(1)) for m in LINE_TOKEN.finditer(without_refs)}
    lines |= {int(m.group(1)) for m in PATH_LINE.finditer(without_refs)}
    for line in sorted(lines - grounding.lines):
        violations.append(
            Violation("UNGROUNDED_LINE", target, f"line {line} is not in the evidence")
        )
    for token in sorted(set(CHECK_TOKEN.findall(text)) - grounding.checks):
        violations.append(
            Violation("UNGROUNDED_IDENTIFIER", target, f"check {token} is not in the evidence")
        )
    for token in sorted(set(CWE_TOKEN.findall(text)) - grounding.cwes):
        violations.append(
            Violation("UNGROUNDED_IDENTIFIER", target, f"{token} does not match these categories")
        )
    for token in sorted(set(AWS_ACTION.findall(without_refs))):
        violations.append(
            Violation(
                "UNGROUNDED_IDENTIFIER",
                target,
                f"AWS action {_short(token, 40)!r} is not in the evidence",
            )
        )
    if ARN_TOKEN.search(text):
        violations.append(
            Violation("UNGROUNDED_IDENTIFIER", target, "an ARN is not in the evidence")
        )
    variables = {v for v in VARIABLE_TOKEN.findall(without_refs) if not v.startswith("CKV")}
    for token in sorted(variables - grounding.variables):
        violations.append(
            Violation(
                "UNGROUNDED_IDENTIFIER",
                target,
                f"variable {_short(token, 40)} is not in the evidence",
            )
        )
    groups = {g.id for g in grounding.packet.groups}
    for token in sorted(set(GROUP_TOKEN.findall(text)) - groups):
        violations.append(Violation("UNKNOWN_REF", target, f"group {token} does not exist"))
    return violations


def _secrets(text: str, target: str) -> list[Violation]:
    if any(pattern.search(text) for pattern in SECRET_PATTERNS):
        return [Violation("SECRET_MATERIAL", target, "output contains credential-like material")]
    for token in HIGH_ENTROPY.findall(text):
        classes = sum(bool(re.search(p, token)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[+/_=-]"))
        if classes >= 3:
            return [
                Violation("SECRET_MATERIAL", target, "output contains a long high-entropy token")
            ]
    return []


def _authority(text: str, target: str, groups: tuple[Group, ...]) -> list[Violation]:
    violations = []
    severe = any(g.severity in {"high", "critical"} for g in groups)
    non_permit = any(g.decision != "permit" for g in groups)
    for sentence in _sentences(text):
        for pattern in AUTHORITY_CLAIMS:
            match = pattern.search(sentence)
            if match and not HYPOTHETICAL.search(sentence[: match.start()]):
                violations.append(
                    Violation(
                        "AUTHORITY_CLAIM",
                        target,
                        f"claim {_short(match.group(0), 40)!r} overrides the policy decision",
                    )
                )
        for pattern in DISMISSALS:
            # The claim's own "not" starts the match; only earlier words make it hypothetical.
            match = pattern.search(sentence)
            if match and non_permit and not HYPOTHETICAL.search(sentence[: match.start()]):
                violations.append(
                    Violation("AUTHORITY_CLAIM", target, "dismisses a finding the policy flagged")
                )
        if (
            severe
            and (match := LOW_RISK.search(sentence))
            and not HYPOTHETICAL.search(sentence[: match.start()])
        ):
            violations.append(
                Violation("AUTHORITY_CLAIM", target, "downplays a high-severity finding")
            )
    if INJECTION_ECHO.search(text):
        violations.append(
            Violation("INJECTION_ECHO", target, "output repeats instruction-like text")
        )
    return violations


def _unsafe(text: str, target: str) -> list[Violation]:
    violations = []
    for sentence in _sentences(text):
        for pattern, reason in UNSAFE_ADVICE:
            if pattern.search(sentence) and not ADVICE_NEGATION.search(sentence):
                violations.append(Violation("UNSAFE_ADVICE", target, reason))
    return violations


def _refs(refs, allowed: set[str], target: str) -> list[Violation]:
    return [
        Violation("UNKNOWN_REF", target, f"ref {_short(str(ref), 40)!r} is not in the evidence")
        for ref in refs
        if ref not in allowed
    ]


def _duplicates(values: list[str], target: str) -> list[Violation]:
    normalized = [re.sub(r"\W+", " ", v).strip().lower() for v in values]
    if len(set(normalized)) != len(normalized):
        return [Violation("DUPLICATE_CONTENT", target, "repeated steps or statements")]
    return []


def check_explanation(item: dict, group: Group, packet: EvidencePacket) -> list[Violation]:
    """Semantic checks for one schema-valid explanation."""
    target = group.id
    grounding = Grounding((group,), packet)
    own_refs = set(group.refs()) | set(packet.scan_refs())
    violations = _refs(item["refs"], own_refs, target)
    for step in item["fix_steps"]:
        violations += _refs(step["refs"], own_refs, target)
    prose = _prose({k: v for k, v in item.items() if k != "escalation" and k != "impact"})
    text = "\n".join(prose)
    violations += _identifiers(text, grounding, target)
    violations += _secrets(text, target)
    violations += _authority(text, target, (group,))
    advice = "\n".join(_prose(item["fix_steps"], item["verify"]))
    violations += _unsafe(advice, target)
    if not re.search(
        PLAYBOOKS[group.category].must_mention, " ".join(_prose(item["fix_steps"])), re.I
    ):
        violations.append(
            Violation(
                "MISSING_REQUIRED_STEP",
                target,
                f"fix steps must cover: {PLAYBOOKS[group.category].must_mention}",
            )
        )
    violations += _duplicates([s["action"] for s in item["fix_steps"]], target)
    if item["headline"].strip().lower() == item["what_happened"].strip().lower():
        violations.append(Violation("DUPLICATE_CONTENT", target, "headline repeats what_happened"))
    return violations


def check_synthesis(item: dict, packet: EvidencePacket) -> list[Violation]:
    target = SYNTHESIS_ID
    grounding = Grounding(packet.groups, packet)
    violations = []
    allowed = grounding.refs
    order = list(packet.priority_order)
    ids = [p["group_id"] for p in item["priorities"]]
    unknown = [g for g in ids if g not in order]
    if unknown:
        violations.append(
            Violation("UNKNOWN_REF", target, f"priorities name unknown groups {unknown[:3]}")
        )
    elif len(set(ids)) != len(ids) or ids != order[: len(ids)]:
        violations.append(
            Violation(
                "PRIORITY_ORDER_CONFLICT",
                target,
                f"priorities must follow {','.join(order)} exactly",
            )
        )
    for priority in item["priorities"]:
        violations += _refs(priority["refs"], allowed, target)
    for risk in item["combined_risks"]:
        if len(set(risk["group_ids"])) < 2 or any(g not in order for g in risk["group_ids"]):
            violations.append(
                Violation("UNKNOWN_REF", target, "combined risks need two or more existing groups")
            )
        violations += _refs(risk["refs"], allowed, target)
    text = "\n".join(_prose(item))
    violations += _identifiers(text, grounding, target)
    violations += _secrets(text, target)
    violations += _authority(text, target, packet.groups)
    violations += _unsafe(item["next_step"], target)
    return violations


def check_explanation_batch(
    payload, packet: EvidencePacket, requested: list[str], synthesis_requested: bool
) -> BatchCheck:
    result = BatchCheck()
    targets = [*requested, *([SYNTHESIS_ID] if synthesis_requested else [])]
    if (
        not isinstance(payload, dict)
        or set(payload) != {"explanations", "synthesis"}
        or not isinstance(payload.get("explanations"), list)
    ):
        for target in targets:
            result.violations[target].append(
                Violation(
                    "SCHEMA", target, "tool input must have explanations (list) and synthesis"
                )
            )
        return result
    seen: set[str] = set()
    for index, item in enumerate(payload["explanations"][: MAX_BATCH * 2]):
        group_id = item.get("group_id") if isinstance(item, dict) else None
        if group_id not in requested:
            result.batch_violations.append(
                Violation(
                    "UNREQUESTED_GROUP",
                    "batch",
                    f"explanation {index} names a group that was not requested",
                )
            )
            continue
        if group_id in seen:
            result.violations[group_id].append(
                Violation("DUPLICATE_GROUP", group_id, "explained more than once")
            )
            result.accepted.pop(group_id, None)
            continue
        seen.add(group_id)
        errors = validate(EXPLANATION, item, f"explanations[{index}]")
        if errors:
            result.violations[group_id] += [Violation("SCHEMA", group_id, e) for e in errors[:8]]
            continue
        semantic = check_explanation(item, packet.group(group_id), packet)
        if semantic:
            result.violations[group_id] += semantic[:12]
        else:
            result.accepted[group_id] = item
    for group_id in requested:
        if group_id not in seen:
            result.violations[group_id].append(
                Violation("MISSING_GROUP", group_id, "no explanation was provided")
            )
    if synthesis_requested:
        synthesis = payload.get("synthesis")
        errors = (
            validate(SYNTHESIS, synthesis, "synthesis")
            if synthesis is not None
            else ["synthesis: required but null"]
        )
        if errors:
            result.violations[SYNTHESIS_ID] += [
                Violation("SCHEMA", SYNTHESIS_ID, e) for e in errors[:8]
            ]
        elif semantic := check_synthesis(synthesis, packet):
            result.violations[SYNTHESIS_ID] += semantic[:12]
        else:
            result.accepted[SYNTHESIS_ID] = synthesis
    if result.batch_violations:
        # An invented group taints the batch: nothing from it is trusted as fully grounded.
        for target in list(result.accepted):
            result.violations[target] += result.batch_violations
            del result.accepted[target]
    return result


def check_answer(payload, packet: EvidencePacket, groups: tuple[Group, ...]) -> list[Violation]:
    target = "ANSWER"
    errors = validate(ANSWER, payload, "answer")
    if errors:
        return [Violation("SCHEMA", target, e) for e in errors[:8]]
    grounding = Grounding(groups or packet.groups, packet)
    violations = _refs(
        payload["refs"],
        {r for g in packet.groups for r in g.refs()} | set(packet.scan_refs()),
        target,
    )
    text = "\n".join(_prose({k: v for k, v in payload.items() if isinstance(v, (str, list))}))
    violations += _identifiers(text, Grounding(packet.groups, packet), target)
    violations += _secrets(text, target)
    violations += _authority(text, target, grounding.groups)
    violations += _unsafe(text, target)
    if not payload["answerable"] and payload["limitation"] == "none":
        violations.append(
            Violation("INCONSISTENT_ANSWER", target, "unanswerable answers need a limitation")
        )
    if payload["answerable"] and groups and not payload["refs"]:
        violations.append(Violation("UNKNOWN_REF", target, "answers about findings must cite refs"))
    return violations


def check_classification(payload, packet: EvidencePacket) -> list[Violation]:
    target = "CLASSIFICATION"
    errors = validate(CLASSIFICATION, payload, "classification")
    if errors:
        return [Violation("SCHEMA", target, e) for e in errors[:8]]
    violations = [
        Violation("UNKNOWN_REF", target, f"group {_short(g, 8)} does not exist")
        for g in payload["group_ids"]
        if packet.group(g) is None
    ]
    if payload["needs_clarification"] and len(payload["clarifying_question"].strip()) < 10:
        violations.append(
            Violation("INCONSISTENT_ANSWER", target, "clarification needs a question")
        )
    return violations
