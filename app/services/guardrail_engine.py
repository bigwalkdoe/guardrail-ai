import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import GuardrailLog, Policy, User

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class PIIDetection:
    type: str
    value_preview: str
    count: int
    risk: str  # low, medium, high, critical


@dataclass
class PromptInjectionResult:
    score: float  # 0-100
    detected: bool
    techniques: List[str] = field(default_factory=list)
    details: str = ""


@dataclass
class PIIDetectionResult:
    score: float  # 0-100
    detected: bool
    items: List[PIIDetection] = field(default_factory=list)
    redacted_text: str = ""


@dataclass
class OutputSafetyResult:
    score: float
    passed: bool
    issues: List[str] = field(default_factory=list)
    details: str = ""


@dataclass
class PolicyResult:
    passed: bool
    violations: List[str] = field(default_factory=list)
    action: str = "allow"  # allow, warn, block


@dataclass
class GuardrailResult:
    risk_score: float  # 0-100
    action: str  # allow, warn, block
    prompt_injection: PromptInjectionResult = field(
        default_factory=PromptInjectionResult
    )
    pii: PIIDetectionResult = field(default_factory=PIIDetectionResult)
    output_safety: Optional[OutputSafetyResult] = None
    policy: PolicyResult = field(default_factory=PolicyResult)
    latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------

PII_PATTERNS: List[tuple] = [
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "medium",
    ),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "critical"),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "critical"),
    ("phone_us", re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"), "medium"),
    ("ip_address", re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "low"),
    ("aws_key", re.compile(r"(?i)AKIA[0-9A-Z]{16}"), "critical"),
    ("slack_token", re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"), "critical"),
    ("github_token", re.compile(r"(?i)gh[pousr]_[A-Za-z0-9_]{36,}"), "critical"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"), "high"),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "critical",
    ),
    ("basic_auth", re.compile(r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"), "critical"),
    (
        "bearer_token",
        re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9-._~+/]+"),
        "critical",
    ),
]

# ---------------------------------------------------------------------------
# Prompt injection patterns
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: List[tuple] = [
    (
        "dan_mode_switch",
        re.compile(
            r"(?i)(from now on|you are (?:now |going to )?|act as |pretend (?:to be|you are))"
        ),
        30.0,
    ),
    (
        "ignore_instructions",
        re.compile(
            r"(?i)(ignore (?:the )?(?:above|previous|all)|"
            r"disregard|forget (?:your|all)|do not follow|skip the)"
        ),
        40.0,
    ),
    (
        "role_play_bypass",
        re.compile(
            r"(?i)(dan |jailbreak|developer mode|debug mode|sudo mode|越南|freedom mode|unfiltered)"
        ),
        50.0,
    ),
    (
        "token_smuggling",
        re.compile(
            r"(?i)(base64|hex|octal|binary)\s*(?:encode|decode|representation|of)"
        ),
        35.0,
    ),
    (
        "delimiter_manip",
        re.compile(
            r"(?i)(ignore\s+(?:the\s+)?(?:above|system|prompt)|===+\s*[A-Z]|---+\s*[A-Z])"
        ),
        45.0,
    ),
    (
        "threat_coercion",
        re.compile(
            r"(?i)(I will (?:harm|hurt|kill|destroy)|"
            r"you (?:must|have to|will) (?:obey|answer|respond)|"
            r"or (?:else|I will))"
        ),
        60.0,
    ),
    (
        "output_formatting",
        re.compile(
            r"(?i)(do not (?:say|state|mention|include|refuse)|"
            r"don\'t (?:say|refuse)|never (?:refuse|say))"
        ),
        35.0,
    ),
    (
        "character_play",
        re.compile(
            r"(?i)(roleplay|role-play|rpg|character\s+ai|persona|chatbot\s+rules?)"
        ),
        25.0,
    ),
    (
        "encoding_bypass",
        re.compile(r"(?i)(rot13|rot-13|caesar|cipher|morse|leetspeak|l33t)"),
        30.0,
    ),
    (
        "system_prompt_leak",
        re.compile(
            r"(?i)(print\s+(?:your|the)\s+(?:system|initial|prompt|instructions)|"
            r"show\s+(?:me\s+)?(?:your|the)\s+(?:system|prompt|instructions))"
        ),
        50.0,
    ),
]

# ---------------------------------------------------------------------------
# Output safety patterns
# ---------------------------------------------------------------------------

OUTPUT_SAFETY_PATTERNS: List[tuple] = [
    (
        "toxic_language",
        re.compile(r"(?i)(\b(idiot|stupid|moron|worthless|kill yourself)\b)"),
        40.0,
    ),
    (
        "hate_speech",
        re.compile(
            r"(?i)(\b(racial|hate|discriminat|bigot)\s+(?:slur|remark|comment|statement)\b)"
        ),
        50.0,
    ),
    (
        "dangerous_content",
        re.compile(
            r"(?i)(how to (?:make|build|create|synthesize)\s+(?:bomb|explosive|weapon|drug|poison))"
        ),
        80.0,
    ),
    (
        "leaked_credential",
        re.compile(
            r'(?i)(password|secret|api[_-]?key|token)\s*(?:is|:|=)\s*[\'"]?[A-Za-z0-9_\-.]{10,}'
        ),
        70.0,
    ),
]


class GuardrailEngine:
    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_prompt(
        self,
        prompt: str,
        user: User,
        tool_id: Optional[int] = None,
    ) -> GuardrailResult:
        import time

        start = time.time()

        injection = self.analyze_prompt_injection(prompt)
        pii = self.detect_pii(prompt)
        policy = self.check_policy_compliance(prompt, user, tool_id)

        scores = []
        if injection.detected:
            scores.append(injection.score)
        if pii.detected:
            scores.append(pii.score)
        if not policy.passed:
            scores.append(60.0)

        risk_score = min(sum(scores) / len(scores), 100) if scores else 0.0

        if risk_score >= 70 or any(v in policy.action for v in ["block"]):
            action = "block"
        elif risk_score >= 35 or policy.action == "warn":
            action = "warn"
        else:
            action = "allow"

        latency = (time.time() - start) * 1000

        self._log_evaluation(
            user_id=user.id,
            org_id=user.org_id,
            tool_id=tool_id,
            prompt=prompt,
            evaluation_type="prompt",
            risk_score=risk_score,
            action=action,
            injection_score=injection.score,
            pii_detected=pii.detected,
            pii_types=[i.type for i in pii.items],
            policy_violations=policy.violations,
            latency_ms=latency,
        )

        return GuardrailResult(
            risk_score=round(risk_score, 1),
            action=action,
            prompt_injection=injection,
            pii=pii,
            policy=policy,
            latency_ms=round(latency, 2),
        )

    def evaluate_output(
        self,
        prompt: str,
        output: str,
        user: User,
    ) -> GuardrailResult:
        import time

        start = time.time()

        injection = self.analyze_prompt_injection(prompt)
        output_safety = self.validate_output_safety(output)
        pii = self.detect_pii(output)

        scores = []

        if injection.detected:
            scores.append(injection.score * 0.5)
        if output_safety.issues:
            scores.append(output_safety.score)
        if pii.detected:
            scores.append(pii.score)

        risk_score = min(sum(scores) / len(scores), 100) if scores else 0.0
        action = (
            "block" if risk_score >= 70 else ("warn" if risk_score >= 35 else "allow")
        )

        latency = (time.time() - start) * 1000

        self._log_evaluation(
            user_id=user.id,
            org_id=user.org_id,
            prompt=prompt,
            evaluation_type="output",
            risk_score=risk_score,
            action=action,
            injection_score=injection.score,
            pii_detected=pii.detected,
            pii_types=[i.type for i in pii.items],
            latency_ms=latency,
        )

        return GuardrailResult(
            risk_score=round(risk_score, 1),
            action=action,
            prompt_injection=injection,
            pii=pii,
            output_safety=output_safety,
            latency_ms=round(latency, 2),
        )

    # ------------------------------------------------------------------
    # Prompt injection detection
    # ------------------------------------------------------------------

    def analyze_prompt_injection(self, text: str) -> PromptInjectionResult:
        if not text:
            return PromptInjectionResult(score=0, detected=False)

        matched: List[str] = []
        max_score = 0.0

        for name, pattern, base_score in INJECTION_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                count = len(matches) if isinstance(matches, list) else 1
                technique_score = min(base_score + (count - 1) * 10, 100)
                max_score = max(max_score, technique_score)
                matched.append(f"{name} ({count})")

        return PromptInjectionResult(
            score=round(min(max_score, 100), 1),
            detected=max_score >= 20,
            techniques=matched,
            details="; ".join(matched) if matched else "No injection patterns detected",
        )

    # ------------------------------------------------------------------
    # PII detection
    # ------------------------------------------------------------------

    def detect_pii(self, text: str) -> PIIDetectionResult:
        if not text:
            return PIIDetectionResult(score=0, detected=False, redacted_text=text)

        items: List[PIIDetection] = []
        redacted = text
        total_risk_score = 0.0

        for name, pattern, risk in PII_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                unique = list(set(matches))
                risk_mult = {"low": 10, "medium": 30, "high": 50, "critical": 70}[risk]
                score_for_type = min(risk_mult + (len(unique) - 1) * 5, 100)
                total_risk_score = max(total_risk_score, score_for_type)

                for val in unique:
                    preview = val[:20] + "..." if len(val) > 20 else val
                    items.append(
                        PIIDetection(
                            type=name,
                            value_preview=preview,
                            count=len(matches),
                            risk=risk,
                        )
                    )
                    redacted = redacted.replace(val, f"[REDACTED:{name}]")

        return PIIDetectionResult(
            score=round(total_risk_score, 1),
            detected=len(items) > 0,
            items=items,
            redacted_text=redacted,
        )

    # ------------------------------------------------------------------
    # Output safety validation
    # ------------------------------------------------------------------

    def validate_output_safety(self, output: str) -> OutputSafetyResult:
        if not output:
            return OutputSafetyResult(score=0, passed=True)

        issues: List[str] = []
        max_score = 0.0

        for name, pattern, base_score in OUTPUT_SAFETY_PATTERNS:
            if pattern.search(output):
                max_score = max(max_score, base_score)
                issues.append(name)

        return OutputSafetyResult(
            score=round(min(max_score, 100), 1),
            passed=max_score < 40,
            issues=issues,
            details="; ".join(issues) if issues else "Output passed safety checks",
        )

    # ------------------------------------------------------------------
    # Policy compliance
    # ------------------------------------------------------------------

    def check_policy_compliance(
        self,
        prompt: str,
        user: User,
        tool_id: Optional[int] = None,
    ) -> PolicyResult:
        violations: List[str] = []
        action = "allow"

        org_id = user.org_id
        policies = (
            self.db.query(Policy)
            .filter(
                Policy.is_active == True,
                (Policy.org_id == org_id) | (Policy.org_id.is_(None)),
            )
            .all()
        )

        for policy in policies:
            restricted = policy.restricted_data_types or []
            for data_type in restricted:
                if data_type.lower() in ["pii", "confidential", "secret"]:
                    pii_check = self.detect_pii(prompt)
                    if pii_check.detected:
                        violations.append(
                            f"Policy '{policy.name}': restricted data type '{data_type}' detected"
                        )
                        if policy.enforcement_mode == "block":
                            action = "block"
                        elif policy.enforcement_mode == "warn" and action != "block":
                            action = "warn"

            if tool_id and policy.allowed_tools:
                if tool_id not in policy.allowed_tools:
                    violations.append(
                        f"Policy '{policy.name}': tool not in allowed list"
                    )
                    if policy.enforcement_mode == "block":
                        action = "block"
                    elif policy.enforcement_mode == "warn" and action != "block":
                        action = "warn"

        return PolicyResult(
            passed=len(violations) == 0, violations=violations, action=action
        )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log_evaluation(
        self,
        user_id: int,
        org_id: Optional[int],
        prompt: str,
        evaluation_type: str,
        risk_score: float,
        action: str,
        injection_score: float,
        pii_detected: bool,
        pii_types: List[str],
        policy_violations: Optional[List[str]] = None,
        latency_ms: float = 0.0,
        tool_id: Optional[int] = None,
    ):
        try:
            log = GuardrailLog(
                org_id=org_id,
                user_id=user_id,
                tool_id=tool_id,
                prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
                prompt_preview=prompt[:200],
                evaluation_type=evaluation_type,
                risk_score=risk_score,
                action_taken=action,
                injection_score=injection_score,
                pii_detected=pii_detected,
                pii_types=pii_types,
                policy_violations=policy_violations or [],
                latency_ms=latency_ms,
            )
            self.db.add(log)
            self.db.commit()
        except Exception as e:
            logger.error(f"Failed to log guardrail evaluation: {e}")
            self.db.rollback()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: Optional[int] = None) -> Dict[str, Any]:
        from sqlalchemy import func

        query = self.db.query(GuardrailLog)
        if org_id:
            query = query.filter(GuardrailLog.org_id == org_id)

        total = query.count()
        blocked = query.filter(GuardrailLog.action_taken == "block").count()
        warned = query.filter(GuardrailLog.action_taken == "warn").count()
        allowed = query.filter(GuardrailLog.action_taken == "allow").count()

        avg_risk = query.with_entities(func.avg(GuardrailLog.risk_score)).scalar() or 0

        top_pii = (
            self.db.query(GuardrailLog.pii_types)
            .filter(GuardrailLog.pii_detected == True)
            .all()
        )
        pii_flat: List[str] = []
        for row in top_pii:
            if row[0]:
                pii_flat.extend(row[0])

        top_violations = (
            self.db.query(GuardrailLog.policy_violations)
            .filter(GuardrailLog.policy_violations.isnot(None))
            .all()
        )
        violation_flat: List[str] = []
        for row in top_violations:
            if row[0]:
                violation_flat.extend(row[0])

        return {
            "total_evaluations": total,
            "blocked": blocked,
            "warned": warned,
            "allowed": allowed,
            "pass_rate": round((allowed / total * 100) if total else 100, 1),
            "avg_risk_score": round(float(avg_risk), 1),
            "most_common_pii": list(set(pii_flat))[:10] if pii_flat else [],
            "most_common_violations": (
                list(set(violation_flat))[:10] if violation_flat else []
            ),
        }

    def get_logs(
        self,
        org_id: Optional[int] = None,
        action: Optional[str] = None,
        user_id: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        query = self.db.query(GuardrailLog)
        if org_id:
            query = query.filter(GuardrailLog.org_id == org_id)
        if action:
            query = query.filter(GuardrailLog.action_taken == action)
        if user_id:
            query = query.filter(GuardrailLog.user_id == user_id)

        logs = (
            query.order_by(GuardrailLog.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        return [
            {
                "id": log.id,
                "user_id": log.user_id,
                "tool_id": log.tool_id,
                "prompt_preview": log.prompt_preview,
                "evaluation_type": log.evaluation_type,
                "risk_score": log.risk_score,
                "action_taken": log.action_taken,
                "injection_score": log.injection_score,
                "pii_detected": log.pii_detected,
                "pii_types": log.pii_types or [],
                "policy_violations": log.policy_violations or [],
                "latency_ms": log.latency_ms,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ]
