from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Boolean,
    ForeignKey,
    Text,
    JSON,
    Float,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, timezone, timezone
from enum import Enum
import uuid

Base = declarative_base()


class UserRole(str, Enum):
    """User role enum for type safety - matching blueprint specification"""

    ADMIN = "admin"
    EMPLOYEE = "employee"
    AUDITOR = "auditor"


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    industry = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))

    # Relationships
    users = relationship("User", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    prompts = relationship("Prompt", back_populates="organization")


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    role = Column(
        String, default=UserRole.EMPLOYEE.value
    )  # admin, auditor, user - using enum for type safety
    department = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))

    # Relationships
    organization = relationship("Organization", back_populates="users")
    api_keys = relationship("APIKey", back_populates="user")
    webhooks = relationship("Webhook", back_populates="user")


class AITool(Base):
    __tablename__ = "ai_tools"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    tool_type = Column(String)  # llm, image_generation, text_to_speech, etc.
    provider = Column(String)  # openai, anthropic, google, etc.
    risk_level = Column(String, default="low")  # low, medium, high, critical
    category = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))


class Policy(Base):
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    rules = Column(JSON)  # Store rules as JSON
    org_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=True
    )  # null = global policy
    enforcement_mode = Column(String, default="warn")  # inform, warn, block
    allowed_tools = Column(JSON, nullable=True)  # List of allowed tool IDs
    restricted_data_types = Column(JSON, nullable=True)  # List of restricted data types
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))

    # Relationships
    organization = relationship("Organization", back_populates="policies")


class Prompt(Base):
    __tablename__ = "prompts"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    content = Column(Text)
    category = Column(String)
    org_id = Column(
        Integer, ForeignKey("organizations.id"), nullable=True
    )  # null = global/approved for all
    allowed_roles = Column(JSON, nullable=True)  # Roles that can use this prompt
    sensitivity_level = Column(String, default="low")  # low, medium, high
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    updated_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None), onupdate=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))

    # Relationships
    organization = relationship("Organization", back_populates="prompts")


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    report_type = Column(String)
    data = Column(JSON)  # Store report data as JSON
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))


class AuditExport(Base):
    """Audit exports table for compliance and reporting"""

    __tablename__ = "audit_exports"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    export_type = Column(String)  # usage, violations, compliance, summary
    generated_by = Column(
        Integer, ForeignKey("users.id"), nullable=True
    )  # Nullable for exports without auth context
    file_path = Column(String, nullable=True)
    filters = Column(JSON, nullable=True)  # Store export filters
    record_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))


class PolicyViolation(Base):
    __tablename__ = "policy_violations"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    usage_id = Column(Integer, ForeignKey("ai_usage_logs.id"))
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=True)
    user_id = Column(
        Integer, ForeignKey("users.id"), nullable=True
    )  # Added for audit trail
    violation_type = Column(
        String
    )  # sensitive_data, unauthorized_tool, role_violation, etc.
    severity = Column(String)  # low, medium, high, critical
    details = Column(Text)
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))


class Usage(Base):
    """Legacy usage table for basic API tracking"""

    __tablename__ = "usage_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    endpoint = Column(String)
    tokens_used = Column(Integer)
    timestamp = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))


class AIUsageLog(Base):
    """AI-specific usage logging table matching the blueprint"""

    __tablename__ = "ai_usage_logs"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(
        String, default=lambda: str(uuid.uuid4()), unique=True, index=True
    )
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    tool_id = Column(Integer, ForeignKey("ai_tools.id"), nullable=True)

    # AI-specific fields
    prompt = Column(Text)
    output_summary = Column(Text)
    ai_model = Column(String, nullable=True)
    usage_type = Column(
        String
    )  # llm, image_generation, text_to_speech, embedding, etc.
    data_type = Column(String)  # internal, public, pii, confidential

    # Policy evaluation result
    policy_result = Column(String, default="allowed")  # allowed, warned, blocked
    policy_message = Column(String, nullable=True)

    # Tokens and cost tracking
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    cost_usd = Column(Float, default=0.0)

    # Metadata
    endpoint = Column(String, nullable=True)
    client_ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    timestamp = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))


# =============================================================================
# SaaS Models (Phase 1 Implementation)
# =============================================================================


class APIKey(Base):
    """API Key model for SaaS authentication and rate limiting."""

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column("key", String, unique=True, index=True)  # Hashed API key
    key_prefix = Column(String, index=True, nullable=True)  # Prefix for display
    user_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String, nullable=True)  # Human-readable name
    rate_limit_rpm = Column(Integer, default=60)  # requests per minute
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    last_used = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="api_keys")
    usage_records = relationship("UsageRecord", back_populates="api_key")


class UsageRecord(Base):
    """Detailed usage tracking for billing and analytics."""

    __tablename__ = "usage_records"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"))
    request_id = Column(String, index=True)  # Link to AIUsageLog.request_id

    # Provider and model details
    provider = Column(String)  # openai, anthropic, local
    model = Column(String)  # gpt-4, claude-3, etc.

    # Token usage
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)

    # Cost calculation
    cost_usd = Column(Float, default=0.0)

    # Metadata
    endpoint = Column(String, nullable=True)
    client_ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    timestamp = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))

    # Relationships
    api_key = relationship("APIKey", back_populates="usage_records")


class BillingPlan(Base):
    """Billing plans for SaaS subscriptions."""

    __tablename__ = "billing_plans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))

    # Plan details
    plan_tier = Column(String)  # starter, growth, enterprise
    monthly_price = Column(Float, default=0.0)

    # Limits
    token_limit = Column(Integer, default=100000)  # monthly token limit
    rate_limit_rpm = Column(Integer, default=60)  # requests per minute

    # Status
    is_active = Column(Boolean, default=True)
    stripe_subscription_id = Column(String, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    updated_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None), onupdate=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))

    # Relationships
    user = relationship("User", back_populates="billing_plans")


# Add relationships to existing models
User.api_keys = relationship("APIKey", back_populates="user")
User.billing_plans = relationship("BillingPlan", back_populates="user")


# =============================================================================
# Cybersecurity Platform Models (Phase 2 - Guardrail Security)
# =============================================================================


class Asset(Base):
    """
    Asset model for cybersecurity platform - stores discovered assets.
    Matches blueprint specification for asset reconnaissance.
    """

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    hostname = Column(String, nullable=True, index=True)
    ip_address = Column(String, index=True)
    service = Column(String, nullable=True)
    version = Column(String, nullable=True)
    exposure_level = Column(String, default="internal")  # internal, external, public
    asset_type = Column(
        String, nullable=True
    )  # web_server, api, database, container, cloud
    cloud_provider = Column(String, nullable=True)  # aws, gcp, azure
    cloud_resource_id = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    discovered_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    last_scanned = Column(DateTime, nullable=True)
    meta_data = Column(JSON, nullable=True)  # Additional asset metadata


class Vulnerability(Base):
    """
    Vulnerability model for storing discovered vulnerabilities and CVE mappings.
    Matches blueprint specification for vulnerability intelligence.
    """

    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    cve_id = Column(String, nullable=True, index=True)  # CVE-2021-41773
    vulnerability_type = Column(String)  # sql_injection, xss, etc.
    description = Column(Text, nullable=True)
    severity = Column(String)  # low, medium, high, critical
    cvss_score = Column(Float, nullable=True)
    exploit_probability = Column(Float, default=0.0)  # 0-100%
    risk_score = Column(
        Float, default=0.0
    )  # Calculated: CVSS * exploit_prob * exposure
    is_exploitable = Column(Boolean, default=False)
    is_patched = Column(Boolean, default=False)
    discovered_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    remediation = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)  # Links to CVE database, patches


class AttackPath(Base):
    """
    Attack path model for storing simulated attack chains.
    Uses graph relationships to model attacker movement.
    """

    __tablename__ = "attack_paths"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    name = Column(String)
    description = Column(Text, nullable=True)
    entry_asset_id = Column(Integer, ForeignKey("assets.id"))
    critical_asset_id = Column(Integer, ForeignKey("assets.id"))
    path_data = Column(JSON)  # Graph path: nodes and edges
    attack_vector = Column(String)  # Initial attack method
    likelihood = Column(Float, default=0.0)  # Probability of success
    impact_score = Column(Float, default=0.0)
    is_simulated = Column(
        Boolean, default=True
    )  # True = simulation, False = real attack
    executed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))


class Alert(Base):
    """
    Security alert model for blue team monitoring.
    """

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    alert_type = Column(String)  # intrusion, anomaly, policy_violation, threat_intel
    title = Column(String)
    description = Column(Text, nullable=True)
    severity = Column(String)  # low, medium, high, critical
    status = Column(
        String, default="open"
    )  # open, investigating, resolved, false_positive
    source = Column(String, nullable=True)  # blue_team, threat_intel, manual
    mitre_tactic = Column(String, nullable=True)  # MITRE ATT&CK tactic
    mitre_technique = Column(String, nullable=True)  # MITRE ATT&CK technique
    indicators = Column(JSON, nullable=True)  # IoCs
    response_action = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)


class ThreatIntel(Base):
    """
    Threat intelligence model for storing threat feeds and indicators.
    """

    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String)  # ip, domain, hash, url
    indicator_value = Column(String, index=True)
    threat_type = Column(String)  # malware, c2, phishing, ransomware
    source = Column(String)  # threat_feed_name
    confidence = Column(Float, default=0.0)  # 0-100%
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    meta_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))


class ScanJob(Base):
    """
    Scan job model for tracking reconnaissance and vulnerability scans.
    """

    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    scan_type = Column(String)  # recon, vuln, attack_sim
    target = Column(String)  # IP, domain, or range
    status = Column(String, default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    results = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))


class Webhook(Base):
    """Webhook model for external integrations."""

    __tablename__ = "webhooks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    name = Column(String(255), nullable=False)
    url = Column(String(2048), nullable=False)
    secret = Column(String(64), nullable=True)

    events = Column(JSON, nullable=False)
    status = Column(String(20), default="active")

    timeout = Column(Integer, default=30)
    retry_count = Column(Integer, default=3)
    retry_delay = Column(Integer, default=5)

    last_triggered_at = Column(DateTime, nullable=True)
    last_status_code = Column(Integer, nullable=True)
    failure_count = Column(Integer, default=0)

    created_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))
    updated_at = Column(DateTime, default=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None), onupdate=lambda: datetime.now(tz=timezone.utc).replace(tzinfo=None))

    # Relationships
    user = relationship("User", back_populates="webhooks")
