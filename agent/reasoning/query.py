"""Deterministic question understanding: sanitize, redact, resolve, classify and rewrite.

User questions are untrusted. Before any model sees one, this module removes invisible
characters and secrets, blocks requests to override policy, reveal secrets or change the
assistant's rules, resolves references ("this", "app.py line 9", "the IAM issue") to evidence
groups, and scores intents. Most questions are then answered without a model, or from already
validated explanations. Only questions that need reasoning reach a model, rewritten into a
canonical form so paraphrases share one cache entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from agent.reasoning.evidence import EvidencePacket, clean

QUERY_VERSION = "query-1"
MAX_QUESTION = 2000
MAX_CONTEXT = 600
NEEDS_GROUP = {"explain_finding", "why_risky", "how_to_fix", "false_positive_challenge"}
EXPLANATION_INTENTS = {"explain_finding", "why_risky", "how_to_fix"}
DETERMINISTIC_INTENTS = {"deploy_readiness", "policy_decision"}
SYNTHESIS_INTENTS = {"prioritize", "scan_overview"}
MODEL_INTENTS = {"false_positive_challenge", "compare", "concept", "general"}

QUESTION_START = re.compile(
    r"(?i)^\s*(who|what|why|how|when|where|which|can|could|should|would|is|are|am|do|does|did|will|may)\b"
)
INJECTION = re.compile(
    r"(?i)\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(instructions?|rules?|prompts?|"
    r"guardrails?|safety|restrictions?|system)\b|system\s*prompt|developer\s*mode|jailbreak|"
    r"\byou are now\b|\bpretend (to be|you are)\b|reveal (your|the) (prompt|instructions)|"
    r"</?\s*system\s*>|\bact as (an? )?(admin|root|unrestricted)"
)
OVERRIDE_STRONG = re.compile(
    r"(?i)\b(mark|flag|set|treat|classify|label|record)\b.{0,30}\bas\s+(safe|approved|resolved|"
    r"fixed|a false positive|false positive|low (risk|severity)|not an issue)\b|"
    r"\b(lower|downgrade|reduce|change|override)\b.{0,20}"
    r"\b(severity|decision|outcome|risk level)\b|"
    r"\b(skip|bypass|override|disable)\b.{0,20}\b(the\s+)?(review|approval|policy|cedar|checkpoint|gate|scanner)\b|"
    r"\b(suppress|silence|whitelist|ignore)\b.{0,15}\b(this|these|that|the|all)\s+(findings?|warnings?|alerts?|issues?)\b"
)
OVERRIDE_IMPERATIVE = re.compile(
    r"(?i)^\s*(please\s+)?(just\s+)?(approve|auto-?approve|merge|deploy|ship|close|dismiss|resolve)\b"
)
SECRET_REQUEST = re.compile(
    r"(?i)\b(show|print|display|reveal|dump|paste|send|output|decode|read out|give me)\b.{0,25}"
    r"\b(secret|key|password|token|credential)s?\b|"
    r"\b(secret|key|password|token|credential)s?\s+(value|string|itself|in plain ?text)\b"
)
SECRET_REQUEST_EXCEPT = re.compile(r"(?i)\b(how|fix|rotate|remove|where|why|store|move)\b")
RUNTIME = re.compile(
    r"(?i)traceback \(most recent call last\)|\b[A-Z][A-Za-z]+(Error|Exception):|stack ?trace|"
    r"\b500 internal server error\b|\bAccessDenied|is not authorized to perform|segmentation fault|"
    r"\b(crash|crashes|crashed|failing|fails|erroring)\b.{0,25}\b(prod|production|runtime|lambda|deploy)"
)
HELP = re.compile(
    r"(?i)^\s*(help|hi|hello|hey|what can you do|how (do|does) (you|this|first commit) work|"
    r"what are you|who are you)\b"
)
DOMAIN = re.compile(
    r"(?i)\b(secrets?|keys?|credentials?|tokens?|passwords?|iam|permissions?|roles?|polic(y|ies)|"
    r"wildcards?|privileges?|auth\w*|log ?in|routes?|endpoints?|api|validat\w*|input|schema|"
    r"env(ironment)?|variables?|config\w*|shell|subprocess|commands?|inject\w*|secur\w*|"
    r"vulnerab\w*|risks?|risky|findings?|scan\w*|issues?|problems?|fix\w*|remediat\w*|deploy\w*|"
    r"merge|release|ship|pull request|cedar|review\w*|approv\w*|severity|critical|code|repo\w*|"
    r"files?|lines?|explain\w*|priorit\w*|false positive|safe|dangerous|exploit\w*|attack\w*)\b"
)
PLURAL = re.compile(
    r"(?i)\b(all|every|these|those|them|everything|each)\b|\b(issues|findings|problems)\b"
)
PRONOUN = re.compile(r"(?i)\b(this|it|that|the (finding|issue|problem|warning))\b")
CATEGORY_WORDS = {
    "secret": (
        r"\b(secrets?|credentials?|api[ _-]?keys?|access[ _-]?keys?|tokens?|passwords?|"
        r"hard-?coded)\b"
    ),
    "iam_wildcard": r"\b(iam|permissions?|roles?|wildcards?|least[- ]privilege|privileges?)\b",
    "missing_auth": (
        r"\b(auth(entication|orization|orisation)?|login|log in|sign[- ]in|"
        r"unauthenticated|unauthori[sz]ed|access control)\b"
    ),
    "missing_input_validation": (
        r"\b(validat\w*|inputs?|payloads?|request body|schemas?|sanitiz\w*)\b"
    ),
    "missing_environment_variable": (
        r"\b(env(ironment)?[ _-]?var(iable)?s?|environment|config(uration)?|\.env)\b"
    ),
    "unsafe_command_execution": r"\b(shell|subprocess|command injection|os\.system)\b",
}
INTENT_PATTERNS = {
    "how_to_fix": (
        (r"\b(fix|fixing|remediat\w*|resolve|patch|mitigat\w*|repair|rotate|secure it)\b", 3),
        (r"\bhow (do|can|should|would|to) (i|we|you)?\b", 2),
        (r"\bwhat (should|do|must) (i|we) (do|change)\b", 3),
        (r"\b(steps?|solution)\b", 1),
    ),
    "why_risky": (
        (r"\bwhy\b.{0,30}\b(risk\w*|danger\w*|bad|problem|matters?|serious|important|care)\b", 3),
        (
            r"\b(risk|risky|dangerous|impact|consequences?|exploit\w*|attack\w*|harm|what "
            r"could happen|what can go wrong)\b",
            2,
        ),
        (r"\bwhy\b.{0,25}\bflagged\b", 3),
    ),
    "explain_finding": (
        (
            r"\b(explain|what (is|are|does) (this|it|that|G\d+)|meaning|mean|tell me about|"
            r"describe|details?)\b",
            2,
        ),
    ),
    "false_positive_challenge": (
        (r"\bfalse[\s-]*positives?\b", 5),
        (
            r"\b(not (a )?real|doesn'?t apply|isn'?t (a|an) (real )?(issue|problem)|"
            r"intentional|on purpose|test (key|data|credential)s?|fake|dummy|placeholder|"
            r"already (protected|handled|fixed))\b",
            3,
        ),
        (r"\b(really|actually)\b.{0,20}\b(issue|problem|vulnerab\w*|risk|finding|dangerous)\b", 2),
    ),
    "prioritize": (
        (
            r"\bpriorit\w*|\b(first|most important|most urgent|in what order|start with|"
            r"biggest|worst)\b",
            3,
        ),
    ),
    "compare": (
        (r"\b(compare|comparison|difference|differ|versus|vs\.?)\b", 4),
        (r"\bwhich (is|one is) (worse|more (serious|dangerous|important))\b", 3),
    ),
    "policy_decision": (
        (
            r"\bwhy\b.{0,40}\b(denied|blocked|needs? (a )?(human )?(review|approval)|flagged "
            r"for review|not (allowed|permitted)|requires? (review|approval))\b",
            5,
        ),
        (r"\b(cedar|policy decision|decision|outcome|human approval|review required)\b", 2),
        (r"\b(who|what) (needs|has|have) to (approve|review)\b", 4),
    ),
    "deploy_readiness": (
        (
            r"\b(can|could|should|may|am|are) (i|we)\b.{0,20}\b(deploy|ship|release|merge|go "
            r"live|launch|publish)\b",
            6,
        ),
        (
            r"\b(ready|safe|ok|okay|good)\b.{0,15}\b(to )?(deploy|ship|release|merge|"
            r"production|go live|launch)\b",
            6,
        ),
    ),
    "scan_overview": (
        (
            r"\b(summary|summari[sz]e|overview|overall|how bad|results?|what did (you|it|the "
            r"scan) find)\b",
            3,
        ),
    ),
    "concept": (
        (
            r"\bwhat (is|are|does) (a |an |the )?(?P<concept>least[- ]privilege|iam|cedar|"
            r"secret scanning|input validation|authori[sz]ation|authentication|shell injection|"
            r"command injection|sql injection|wildcards?|environment variables?|prompt "
            r"injection|gitleaks|semgrep|checkov|a hardcoded secret|hardcoded secrets?)\b",
            6,
        ),
        (r"\b(concept|in general|generally|definition)\b", 2),
    ),
}
STOPWORDS = frozenset(
    "a an the is are am was were be been i we you it this that these those my our your to of in "
    "on for and or but with about how what why when where which who can could should would do "
    "does did will may me please just really actually finding findings issue issues problem".split()
)


@dataclass(frozen=True)
class EnhancedQuery:
    text: str
    intents: tuple[str, ...]
    group_ids: tuple[str, ...]
    handling: str  # blocked | clarify | deterministic | explanations | synthesis | model | classify
    block_reason: str | None = None
    concept: str | None = None
    user_context: str | None = None
    confidence: float = 1.0
    difficulty: str | None = None
    flags: tuple[str, ...] = ()

    def public(self) -> dict:
        return {
            "intents": list(self.intents),
            "group_ids": list(self.group_ids),
            "handling": self.handling,
            "block_reason": self.block_reason,
            "concept": self.concept,
            "confidence": round(self.confidence, 2),
            "difficulty": self.difficulty,
            "flags": list(self.flags),
            "version": QUERY_VERSION,
        }

    def canonical(self) -> dict:
        # Wording is dropped unless it carries context the canonical rewrite would lose.
        return {
            "intents": sorted(self.intents),
            "groups": list(self.group_ids),
            "concept": self.concept,
            "context": (self.user_context or "").lower() or None,
            "general_text": self.text.lower() if self.intents == ("general",) else None,
        }

    def rewritten(self) -> str:
        groups = ", ".join(self.group_ids) or "the scan"
        templates = {
            "false_positive_challenge": f"Could {groups} not apply here, and how can a "
            "reviewer verify that without dismissing the finding?",
            "compare": f"How do {groups} compare, and which should be fixed first?",
            "concept": f"What is {self.concept or 'this security concept'}, and how does it "
            "relate to this scan?",
        }
        return " ".join(templates[i] for i in self.intents if i in templates) or self.text


def _score(text: str) -> tuple[dict[str, int], str | None]:
    scores, concept = {}, None
    for intent, patterns in INTENT_PATTERNS.items():
        total = 0
        for pattern, weight in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                total += weight
                if intent == "concept" and match.groupdict().get("concept"):
                    concept = match.group("concept").lower()
        if total:
            scores[intent] = total
    return scores, concept


def _references(text: str, packet: EvidencePacket) -> tuple[list[str], set[str]]:
    flags: set[str] = set()
    found: list[str] = []
    valid = {g.id for g in packet.groups}
    for token in re.findall(r"\bG[1-9][0-9]{0,2}\b", text):
        if token in valid:
            found.append(token)
        else:
            flags.add("unknown_group_reference")
    lowered = text.lower()
    lines = {int(n) for n in re.findall(r"(?i)\bline\s+(\d{1,6})\b", text)}
    for group in packet.groups:
        for location in group.locations:
            name = location.path.rsplit("/", 1)[-1].lower()
            mentioned = location.path.lower() in lowered or (
                len(name) >= 4
                and "." in name
                and re.search(rf"(?<![\w.-]){re.escape(name)}\b", lowered)
            )
            if mentioned and (not lines or location.line in lines):
                found.append(group.id)
        if any(
            fid.startswith(token)
            for fid in group.finding_ids
            for token in re.findall(r"\b[0-9a-f]{8,20}\b", lowered)
        ):
            found.append(group.id)
    if not found:
        for category, pattern in CATEGORY_WORDS.items():
            if re.search(pattern, text, re.I):
                found += [g.id for g in packet.groups if g.category == category]
    ordered = [g.id for g in packet.groups if g.id in set(found)]
    return ordered, flags


def _residual_context(text: str, packet: EvidencePacket) -> str | None:
    residue = re.sub(r"\bG[1-9][0-9]{0,2}\b", " ", text)
    for group in packet.groups:
        for location in group.locations:
            residue = residue.replace(location.path, " ")
    words = [
        w for w in re.findall(r"[A-Za-z][A-Za-z'-]{2,}", residue) if w.lower() not in STOPWORDS
    ]
    for patterns in INTENT_PATTERNS.values():
        for pattern, _ in patterns:
            words = [w for w in words if not re.fullmatch(pattern, w, re.I)]
    if len(words) < 6:
        return None
    return clean(text, MAX_CONTEXT).text


def enhance(question: str, packet: EvidencePacket) -> EnhancedQuery:
    cleaned = clean(question if isinstance(question, str) else "", MAX_QUESTION)
    text = cleaned.text
    flags = {
        name
        for name, on in (("secret_redacted", cleaned.redacted), ("truncated", cleaned.truncated))
        if on
    }
    if not text:
        return EnhancedQuery("", (), (), "clarify", flags=tuple(sorted(flags)), confidence=0.0)
    blocked = (
        ("injection_attempt", INJECTION.search(text)),
        (
            "authorization_override",
            OVERRIDE_STRONG.search(text)
            or (OVERRIDE_IMPERATIVE.search(text) and not QUESTION_START.search(text)),
        ),
        (
            "secret_disclosure",
            SECRET_REQUEST.search(text) and not SECRET_REQUEST_EXCEPT.search(text),
        ),
        ("runtime_error", RUNTIME.search(text)),
    )
    groups, reference_flags = _references(text, packet)
    flags |= reference_flags
    for reason, matched in blocked:
        if matched:
            return EnhancedQuery(
                text, (), tuple(groups), "blocked", reason, flags=tuple(sorted(flags))
            )
    has_path = any(loc.path.lower() in text.lower() for g in packet.groups for loc in g.locations)
    if HELP.search(text) and not DOMAIN.search(text):
        return EnhancedQuery(text, (), (), "blocked", "help", flags=tuple(sorted(flags)))
    if not (DOMAIN.search(text) or re.search(r"\bG[1-9]\d{0,2}\b", text) or has_path):
        return EnhancedQuery(text, (), (), "blocked", "out_of_scope", flags=tuple(sorted(flags)))

    scores, concept = _score(text)
    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    if not ranked:
        intents, confidence = (("explain_finding",), 0.6) if groups else (("general",), 0.3)
    else:
        top = ranked[0][1]
        intents = tuple(name for name, score in ranked if score >= max(3, top - 2))[:2] or (
            ranked[0][0],
        )
        second = ranked[1][1] if len(ranked) > 1 else 0
        confidence = top / (top + second) if second else 1.0
    if "concept" in intents and not groups:
        intents = ("concept",)
    if "prioritize" in scores and not re.findall(r"\bG[1-9][0-9]{0,2}\b", text):
        # "What should I fix first?" asks for an order, not the fix for one finding.
        intents = tuple(i for i in intents if i not in EXPLANATION_INTENTS) or ("prioritize",)
        if "prioritize" not in intents:
            intents = ("prioritize", *intents)[:2]
    if (
        PLURAL.search(text)
        and (not groups or len(groups) < len(packet.groups))
        and not reference_flags
    ):
        explicit = re.findall(r"\bG[1-9][0-9]{0,2}\b", text)
        if (
            not explicit
            and not has_path
            and not any(re.search(p, text, re.I) for p in CATEGORY_WORDS.values())
        ):
            groups = [g.id for g in packet.groups]
            flags.add("all_groups")
    if (
        not groups
        and len(packet.groups) == 1
        and (PRONOUN.search(text) or set(intents) & NEEDS_GROUP)
    ):
        groups = [packet.groups[0].id]
        flags.add("single_group_resolved")
    query = EnhancedQuery(
        text=text,
        intents=intents,
        group_ids=tuple(groups),
        handling="",
        concept=concept,
        confidence=confidence,
        flags=tuple(sorted(flags)),
    )
    return plan(query, packet)


def plan(query: EnhancedQuery, packet: EvidencePacket) -> EnhancedQuery:
    """Choose the cheapest handling that can answer the (possibly reclassified) query."""
    intents = set(query.intents)
    groups = list(query.group_ids)
    if not packet.groups and intents - {"concept", "general"}:
        return replace(query, handling="deterministic")
    if intents & NEEDS_GROUP and not groups:
        return replace(query, handling="clarify")
    if "compare" in intents and len(groups) < 2:
        if 2 <= len(packet.groups) <= 4:
            groups = [g.id for g in packet.groups]
        else:
            return replace(query, handling="clarify")
    if intents <= DETERMINISTIC_INTENTS:
        handling = "deterministic"
    elif intents <= EXPLANATION_INTENTS | DETERMINISTIC_INTENTS:
        handling = "explanations"
    elif intents <= SYNTHESIS_INTENTS | DETERMINISTIC_INTENTS:
        handling = "synthesis"
    elif query.intents == ("general",) and query.confidence < 0.5:
        handling = "classify"
    else:
        handling = "model"
    context = _residual_context(query.text, packet) if handling == "model" else None
    return replace(query, group_ids=tuple(groups), handling=handling, user_context=context)
