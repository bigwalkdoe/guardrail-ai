from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from enum import Enum


class UsageType(str, Enum):
    LLM = "llm"
    IMAGE_GENERATION = "image_generation"
    TEXT_TO_SPEECH = "text_to_speech"
    EMBEDDING = "embedding"
    CODE_GENERATION = "code_generation"
    TRANSLATION = "translation"
    OTHER = "other"


class DataType(str, Enum):
    INTERNAL = "internal"
    PUBLIC = "public"
    PII = "pii"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class PolicyResult(str, Enum):
    ALLOWED = "allowed"
    WARNED = "warned"
    BLOCKED = "blocked"


class EnforcementMode(str, Enum):
    INFORM = "inform"
    WARN = "warn"
    BLOCK = "block"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Organization schemas
class OrganizationBase(BaseModel):
    name: str
    industry: Optional[str] = None


class OrganizationCreate(OrganizationBase):
    pass


class Organization(OrganizationBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# User schemas
class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str
    department: Optional[str] = None
    role: Optional[str] = "employee"


class User(UserBase):
    id: int
    is_active: bool
    org_id: Optional[int] = None
    role: str = "user"
    department: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    csrf_token: Optional[str] = None


class UserResponse(BaseModel):
    id: int
    email: str
    org_id: Optional[int] = None
    role: str = "user"
    department: Optional[str] = None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# AI Tool schemas
class AIToolBase(BaseModel):
    name: str
    tool_type: str
    provider: str
    risk_level: str = "low"
    category: Optional[str] = None


class AIToolCreate(AIToolBase):
    pass


class AITool(AIToolBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Policy schemas
class PolicyBase(BaseModel):
    name: str
    description: Optional[str] = None
    rules: Optional[dict] = None


class PolicyCreate(PolicyBase):
    org_id: Optional[int] = None
    enforcement_mode: EnforcementMode = EnforcementMode.WARN
    allowed_tools: Optional[list] = None
    restricted_data_types: Optional[list] = None


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rules: Optional[dict] = None
    enforcement_mode: Optional[EnforcementMode] = None
    allowed_tools: Optional[list] = None
    restricted_data_types: Optional[list] = None
    is_active: Optional[bool] = None


class Policy(PolicyBase):
    id: int
    org_id: Optional[int] = None
    enforcement_mode: str
    allowed_tools: Optional[list] = None
    restricted_data_types: Optional[list] = None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Prompt schemas
class PromptBase(BaseModel):
    name: str
    content: str
    category: str


class PromptCreate(PromptBase):
    org_id: Optional[int] = None
    allowed_roles: Optional[list] = None
    sensitivity_level: str = "low"


class PromptUpdate(BaseModel):
    name: Optional[str] = None
    content: Optional[str] = None
    category: Optional[str] = None
    allowed_roles: Optional[list] = None
    sensitivity_level: Optional[str] = None
    is_active: Optional[bool] = None


class Prompt(PromptBase):
    id: int
    org_id: Optional[int] = None
    allowed_roles: Optional[list] = None
    sensitivity_level: str = "low"
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PromptValidationRequest(BaseModel):
    prompt: str


class PromptValidationResponse(BaseModel):
    is_safe: bool
    confidence: float
    flags: list[str] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)


# Policy Violation schemas
class PolicyViolationBase(BaseModel):
    org_id: Optional[int] = None
    usage_id: int
    policy_id: Optional[int] = None
    user_id: Optional[int] = None  # Added for complete audit trail
    violation_type: str
    severity: Severity
    details: str


class PolicyViolationCreate(PolicyViolationBase):
    pass


class PolicyViolation(PolicyViolationBase):
    id: int
    resolved: bool
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyViolationUpdate(BaseModel):
    resolved: Optional[bool] = None


# Report schemas
class ReportBase(BaseModel):
    title: str
    description: Optional[str] = None
    report_type: str
    data: Optional[dict] = None


class ReportCreate(ReportBase):
    pass


class Report(ReportBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# Legacy Usage schemas (kept for backwards compatibility)
class UsageBase(BaseModel):
    user_id: int
    endpoint: str
    tokens_used: int


class UsageCreate(UsageBase):
    pass


class Usage(UsageBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True


# AI Usage Log schemas - matching the blueprint API
class AIUsageLogBase(BaseModel):
    org_id: Optional[int] = None
    user_id: int
    tool_id: Optional[int] = None
    prompt: str
    usage_type: UsageType
    data_type: DataType
    output_summary: Optional[str] = None
    ai_model: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    endpoint: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None


class AIUsageLogCreate(AIUsageLogBase):
    pass


class AIUsageLog(AIUsageLogBase):
    id: int
    request_id: str
    policy_result: str
    policy_message: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True


# Request/Response for POST /usage/log endpoint (blueprint API)
class AIUsageLogRequest(BaseModel):
    """Request body matching the blueprint's POST /usage/log"""

    org_id: Optional[str] = None
    user_id: str
    tool_id: Optional[str] = None
    prompt: str
    data_type: DataType
    usage_type: UsageType


class AIUsageLogResponse(BaseModel):
    """Response body matching the blueprint's POST /usage/log response"""

    policy_result: PolicyResult
    message: Optional[str] = None
    request_id: str
    # Full log entry for reference
    log_entry: Optional[AIUsageLog] = None


# Audit Export schemas
class AuditExportBase(BaseModel):
    org_id: Optional[int] = None
    export_type: str
    filters: Optional[dict] = None


class AuditExportCreate(AuditExportBase):
    generated_by: int


class AuditExport(AuditExportBase):
    id: int
    generated_by: int
    file_path: Optional[str] = None
    record_count: int = 0
    created_at: datetime

    class Config:
        from_attributes = True


# =============================================================================
# SaaS API Key Schemas
# =============================================================================


class APIKeyBase(BaseModel):
    name: Optional[str] = None
    rate_limit_rpm: int = Field(default=60, ge=1, le=1000)


class APIKeyCreate(APIKeyBase):
    user_id: int


class APIKeyUpdate(APIKeyBase):
    is_active: Optional[bool] = None


class APIKeyMasked(APIKeyBase):
    id: int
    key_prefix: Optional[str] = None
    user_id: int
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime] = None

    class Config:
        from_attributes = True


class APIKeyCreateResponse(APIKeyMasked):
    key: str


# =============================================================================
# SaaS Usage Record Schemas
# =============================================================================


class UsageRecordBase(BaseModel):
    api_key_id: int
    request_id: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    endpoint: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None


class UsageRecordCreate(UsageRecordBase):
    pass


class UsageRecord(UsageRecordBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True


# =============================================================================
# SaaS Billing Plan Schemas
# =============================================================================


class BillingPlanBase(BaseModel):
    plan_tier: str
    monthly_price: float = Field(default=0.0, ge=0)
    token_limit: int = Field(default=100000, ge=0)
    rate_limit_rpm: int = Field(default=60, ge=1)


class BillingPlanCreate(BillingPlanBase):
    user_id: int


class BillingPlanUpdate(BaseModel):
    plan_tier: Optional[str] = None
    monthly_price: Optional[float] = None
    token_limit: Optional[int] = None
    rate_limit_rpm: Optional[int] = None
    is_active: Optional[bool] = None
    stripe_subscription_id: Optional[str] = None


class BillingPlan(BillingPlanBase):
    id: int
    user_id: int
    is_active: bool
    stripe_subscription_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# =============================================================================
# SaaS Proxy Schemas
# =============================================================================


class AIProxyRequest(BaseModel):
    """Request schema for the AI proxy endpoint."""

    prompt: str
    model: str = "gpt-4o-mini"
    provider: Optional[str] = None  # openai, anthropic, local
    data_type: DataType = DataType.PUBLIC
    usage_type: UsageType = UsageType.LLM
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    api_key: str  # Customer's API key for authentication


class AIProxyResponse(BaseModel):
    """Response schema for the AI proxy endpoint."""

    response: str
    model: str
    provider: str
    usage: dict  # token usage info
    cost_usd: float
    policy_result: str  # allowed, warned, blocked
    policy_message: Optional[str] = None
    request_id: str
    redactions: list[str] = Field(default_factory=list)


# =============================================================================
# Cybersecurity Platform Schemas (Phase 2 - Guardrail Security)
# =============================================================================


class AssetBase(BaseModel):
    hostname: Optional[str] = None
    ip_address: str
    service: Optional[str] = None
    version: Optional[str] = None
    exposure_level: str = "internal"
    asset_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_resource_id: Optional[str] = None
    metadata: Optional[dict] = None


class AssetCreate(AssetBase):
    org_id: Optional[int] = None


class Asset(AssetBase):
    id: int
    org_id: Optional[int] = None
    is_active: bool
    discovered_at: datetime
    last_scanned: Optional[datetime] = None

    class Config:
        from_attributes = True


class VulnerabilityBase(BaseModel):
    asset_id: int
    cve_id: Optional[str] = None
    vulnerability_type: str
    description: Optional[str] = None
    severity: str
    cvss_score: Optional[float] = None
    exploit_probability: float = 0.0
    is_exploitable: bool = False
    is_patched: bool = False
    remediation: Optional[str] = None
    references: Optional[dict] = None


class VulnerabilityCreate(VulnerabilityBase):
    org_id: Optional[int] = None


class Vulnerability(VulnerabilityBase):
    id: int
    org_id: Optional[int] = None
    risk_score: float
    discovered_at: datetime

    class Config:
        from_attributes = True


class AttackPathBase(BaseModel):
    name: str
    description: Optional[str] = None
    entry_asset_id: int
    critical_asset_id: int
    path_data: dict  # Graph path: nodes and edges
    attack_vector: str
    likelihood: float = 0.0
    impact_score: float = 0.0
    is_simulated: bool = True


class AttackPathCreate(AttackPathBase):
    org_id: Optional[int] = None


class AttackPath(AttackPathBase):
    id: int
    org_id: Optional[int] = None
    executed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class AlertBase(BaseModel):
    asset_id: Optional[int] = None
    alert_type: str
    title: str
    description: Optional[str] = None
    severity: str
    source: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    indicators: Optional[dict] = None
    response_action: Optional[str] = None


class AlertCreate(AlertBase):
    org_id: Optional[int] = None


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    response_action: Optional[str] = None


class Alert(AlertBase):
    id: int
    org_id: Optional[int] = None
    status: str
    created_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[int] = None

    class Config:
        from_attributes = True


class ThreatIntelBase(BaseModel):
    indicator_type: str  # ip, domain, hash, url
    indicator_value: str
    threat_type: str  # malware, c2, phishing, ransomware
    source: str
    confidence: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Optional[dict] = None


class ThreatIntelCreate(ThreatIntelBase):
    pass


class ThreatIntel(ThreatIntelBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ScanJobBase(BaseModel):
    scan_type: str  # recon, vuln, attack_sim
    target: str


class ScanJobCreate(ScanJobBase):
    org_id: Optional[int] = None
    created_by: Optional[int] = None


class ScanJob(ScanJobBase):
    id: int
    org_id: Optional[int] = None
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Optional[dict] = None
    error_message: Optional[str] = None
    created_by: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ReconRequest(BaseModel):
    """Request for reconnaissance scan."""

    target: str  # domain, IP, or range
    scan_types: list[str] = Field(default_factory=lambda: ["subdomain", "port", "tech"])


class VulnScanRequest(BaseModel):
    """Request for vulnerability scan."""

    asset_ids: Optional[list[int]] = None
    target: Optional[str] = None
    scan_depth: str = "standard"  # quick, standard, deep


class AttackSimRequest(BaseModel):
    """Request for attack simulation."""

    entry_asset_id: int
    target_asset_id: int
    attack_scenario: Optional[str] = None  # sql_injection, privilege_escalation, etc.


class AIDecisionRequest(BaseModel):
    """Request for AI decision engine analysis."""

    query: str
    context: Optional[dict] = None
    analysis_type: str = "general"  # general, threat, remediation


class AIDecisionResponse(BaseModel):
    """Response from AI decision engine."""

    analysis: str
    recommendations: list[str] = Field(default_factory=list)
    risk_level: str
    confidence: float


# =============================================================================
# Guardrail Evaluation Schemas
# =============================================================================


class GuardrailEvaluateRequest(BaseModel):
    prompt: str
    tool_id: Optional[int] = None


class GuardrailEvaluateOutputRequest(BaseModel):
    prompt: str
    output: str
    tool_id: Optional[int] = None


class PIIDetectionItem(BaseModel):
    type: str
    value_preview: str
    count: int
    risk: str


class PromptInjectionResult(BaseModel):
    score: float
    detected: bool
    techniques: list[str] = Field(default_factory=list)
    details: str = ""


class PIIDetectionResult(BaseModel):
    score: float
    detected: bool
    items: list[PIIDetectionItem] = Field(default_factory=list)
    redacted_text: str = ""


class OutputSafetyResult(BaseModel):
    score: float
    passed: bool
    issues: list[str] = Field(default_factory=list)
    details: str = ""


class PolicyResult(BaseModel):
    passed: bool
    violations: list[str] = Field(default_factory=list)
    action: str = "allow"


class GuardrailEvaluateResponse(BaseModel):
    risk_score: float
    action: str
    prompt_injection: PromptInjectionResult
    pii: PIIDetectionResult
    output_safety: Optional[OutputSafetyResult] = None
    policy: PolicyResult
    latency_ms: float = 0.0


class GuardrailLogEntry(BaseModel):
    id: int
    user_id: int
    tool_id: Optional[int] = None
    prompt_preview: str
    evaluation_type: str
    risk_score: float
    action_taken: str
    injection_score: float
    pii_detected: bool
    pii_types: list[str] = Field(default_factory=list)
    policy_violations: list[str] = Field(default_factory=list)
    latency_ms: float
    created_at: str


class GuardrailStats(BaseModel):
    total_evaluations: int
    blocked: int
    warned: int
    allowed: int
    pass_rate: float
    avg_risk_score: float
    most_common_pii: list[str] = Field(default_factory=list)
    most_common_violations: list[str] = Field(default_factory=list)


class GuardrailRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: str = "injection"
    pattern: str
    action: str = "warn"
    severity: str = "medium"


class GuardrailRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    pattern: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    is_active: Optional[bool] = None


class GuardrailRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    category: str
    pattern: str
    action: str
    severity: str
    is_active: bool
    created_at: str


# =============================================================================
# Password Reset Schemas
# =============================================================================


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    password: str


class MFASetupResponse(BaseModel):
    secret: str
    uri: str
    qr_code_url: str


class MFAVerifyRequest(BaseModel):
    code: str


class MFAChallengeRequest(BaseModel):
    session_token: str
    code: str


class MFADisableRequest(BaseModel):
    password: str


class SessionInvalidateResponse(BaseModel):
    message: str
    new_token_version: int
