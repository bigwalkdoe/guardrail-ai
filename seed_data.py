from datetime import datetime, timezone, timedelta
import random
from sqlalchemy.orm import Session
from app.models import (
    Base,
    User,
    Organization,
    AITool,
    Policy,
    Prompt,
    AIUsageLog,
    Alert,
    APIKey,
)

DEMO_PASSWORD_HASH = "$2b$12$5bZa8Z5.5q63sS2opuAaaOgvMLNT0SLGXzQYHVqsJfEglYRix3z.u"


def seed_organizations(db: Session):
    """Create demo organizations."""
    orgs = [
        Organization(name="Acme Corp", industry="Technology"),
        Organization(name="HealthFirst Hospital", industry="Healthcare"),
        Organization(name="Global Finance Inc", industry="Finance"),
        Organization(name="EduTech Solutions", industry="Education"),
    ]
    for org in orgs:
        db.add(org)
    db.commit()
    return orgs


def seed_users(db: Session, orgs: list):
    """Create demo users."""
    users = [
        User(
            email="admin@acme.com",
            hashed_password=DEMO_PASSWORD_HASH,
            role="admin",
            org_id=orgs[0].id,
            department="IT",
            is_active=True,
        ),
        User(
            email="security@acme.com",
            hashed_password=DEMO_PASSWORD_HASH,
            role="auditor",
            org_id=orgs[0].id,
            department="Security",
            is_active=True,
        ),
        User(
            email="developer@acme.com",
            hashed_password=DEMO_PASSWORD_HASH,
            role="employee",
            org_id=orgs[0].id,
            department="Engineering",
            is_active=True,
        ),
        User(
            email="analyst@acme.com",
            hashed_password=DEMO_PASSWORD_HASH,
            role="employee",
            org_id=orgs[0].id,
            department="Data Analytics",
            is_active=True,
        ),
        User(
            email="admin@healthfirst.com",
            hashed_password=DEMO_PASSWORD_HASH,
            role="admin",
            org_id=orgs[1].id,
            department="IT",
            is_active=True,
        ),
        User(
            email="compliance@healthfirst.com",
            hashed_password=DEMO_PASSWORD_HASH,
            role="auditor",
            org_id=orgs[1].id,
            department="Compliance",
            is_active=True,
        ),
        User(
            email="doctor@healthfirst.com",
            hashed_password=DEMO_PASSWORD_HASH,
            role="employee",
            org_id=orgs[1].id,
            department="Medical",
            is_active=True,
        ),
    ]
    for user in users:
        db.add(user)
    db.commit()
    return users


def seed_ai_tools(db: Session):
    """Create demo AI tools."""
    tools = [
        AITool(
            name="GPT-4",
            tool_type="llm",
            provider="OpenAI",
            risk_level="medium",
            category="Text Generation",
        ),
        AITool(
            name="Claude 3",
            tool_type="llm",
            provider="Anthropic",
            risk_level="medium",
            category="Text Generation",
        ),
        AITool(
            name="Gemini Pro",
            tool_type="llm",
            provider="Google",
            risk_level="medium",
            category="Text Generation",
        ),
        AITool(
            name="DALL-E 3",
            tool_type="image_generation",
            provider="OpenAI",
            risk_level="high",
            category="Image Generation",
        ),
        AITool(
            name="Midjourney",
            tool_type="image_generation",
            provider="Midjourney",
            risk_level="high",
            category="Image Generation",
        ),
        AITool(
            name="Whisper",
            tool_type="speech_to_text",
            provider="OpenAI",
            risk_level="low",
            category="Audio",
        ),
        AITool(
            name="Eleven Labs",
            tool_type="text_to_speech",
            provider="Eleven Labs",
            risk_level="medium",
            category="Audio",
        ),
        AITool(
            name="GitHub Copilot",
            tool_type="code_generation",
            provider="GitHub",
            risk_level="medium",
            category="Code",
        ),
        AITool(
            name="CodeWhisperer",
            tool_type="code_generation",
            provider="AWS",
            risk_level="medium",
            category="Code",
        ),
        AITool(
            name="DeepL",
            tool_type="translation",
            provider="DeepL",
            risk_level="low",
            category="Translation",
        ),
        AITool(
            name="Azure AI Search",
            tool_type="search",
            provider="Microsoft",
            risk_level="medium",
            category="Search",
        ),
        AITool(
            name="Hugging Face",
            tool_type="llm",
            provider="Hugging Face",
            risk_level="medium",
            category="Text Generation",
        ),
    ]
    for tool in tools:
        db.add(tool)
    db.commit()
    return tools


def seed_policies(db: Session, orgs: list, tools: list):
    """Create demo policies."""
    policies = [
        Policy(
            name="LLM Usage Policy",
            description="Guidelines for using Large Language Models",
            rules={
                "max_tokens": 10000,
                "allowed_categories": ["text_generation", "code_generation"],
                "blocked_topics": ["harmful_content", "illegal_activities"],
                "require_approval": False,
            },
            enforcement_mode="warn",
            is_active=True,
        ),
        Policy(
            name="Image Generation Policy",
            description="Rules for AI image generation",
            rules={
                "allowed_providers": ["openai", "midjourney"],
                "blocked_content_types": ["violence", "nsfw"],
                "require_approval": True,
                "watermark_required": True,
            },
            enforcement_mode="block",
            org_id=orgs[0].id,
            is_active=True,
        ),
        Policy(
            name="Healthcare Data Policy",
            description="HIPAA compliance for AI tools",
            rules={
                "allowed_tools": [tools[0].id, tools[1].id],
                "phi_blocked": True,
                "audit_required": True,
                "data_retention_days": 90,
            },
            enforcement_mode="block",
            org_id=orgs[1].id,
            is_active=True,
        ),
        Policy(
            name="Finance Data Policy",
            description="Financial data handling with AI",
            rules={
                "allowed_tools": [tools[0].id],
                "pii_blocked": True,
                "audit_required": True,
                "encryption_required": True,
            },
            enforcement_mode="block",
            org_id=orgs[2].id,
            is_active=True,
        ),
        Policy(
            name="Code Generation Policy",
            description="Guidelines for AI code assistance",
            rules={
                "allowed_providers": ["github", "aws"],
                "scan_for_secrets": True,
                "license_check": True,
                "review_required": True,
            },
            enforcement_mode="warn",
            org_id=orgs[0].id,
            is_active=True,
        ),
    ]
    for policy in policies:
        db.add(policy)
    db.commit()
    return policies


def seed_prompts(db: Session, orgs: list):
    """Create demo prompts."""
    prompts = [
        Prompt(
            name="Security Analysis",
            content="Analyze the following code for security vulnerabilities: {code}",
            category="security",
            allowed_roles=["admin", "auditor"],
            sensitivity_level="high",
        ),
        Prompt(
            name="Code Review",
            content="Review this code for best practices and potential issues: {code}",
            category="development",
            allowed_roles=["admin", "employee"],
            sensitivity_level="medium",
        ),
        Prompt(
            name="Data Summary",
            content="Summarize the following data in a clear format: {data}",
            category="analytics",
            allowed_roles=["admin", "employee"],
            sensitivity_level="low",
        ),
        Prompt(
            name="Documentation",
            content="Generate documentation for the following API: {api_spec}",
            category="documentation",
            allowed_roles=["admin", "employee"],
            sensitivity_level="low",
        ),
        Prompt(
            name="Healthcare Compliance Check",
            content="Check if this content complies with HIPAA regulations: {content}",
            category="compliance",
            org_id=orgs[1].id,
            allowed_roles=["admin", "auditor"],
            sensitivity_level="high",
        ),
        Prompt(
            name="Financial Report Generation",
            content="Generate a financial report from the following data: {data}",
            category="reporting",
            org_id=orgs[2].id,
            allowed_roles=["admin"],
            sensitivity_level="high",
        ),
    ]
    for prompt in prompts:
        db.add(prompt)
    db.commit()
    return prompts


def seed_audit_logs(db: Session, users: list, tools: list):
    """Create demo AI usage logs (audit trail)."""
    actions = [
        "login",
        "logout",
        "prompt_request",
        "tool_used",
        "policy_violation",
        "scan_completed",
    ]
    data_types = ["internal", "public", "pii", "confidential"]
    policy_results = ["allowed", "warned", "blocked"]

    logs = []
    for i in range(50):
        user = random.choice(users)
        tool = random.choice(tools) if random.random() > 0.3 else None

        log = AIUsageLog(
            org_id=user.org_id,
            user_id=user.id,
            tool_id=tool.id if tool else None,
            prompt=f"Demo prompt {i}: {random.choice(['Analyze code', 'Generate report', 'Create summary'])}",
            output_summary=f"Demo output for prompt {i}",
            ai_model=tool.name if tool else "GPT-4",
            usage_type=tool.tool_type if tool else "llm",
            data_type=random.choice(data_types),
            policy_result=random.choice(policy_results),
            policy_message="Demo policy check" if random.random() > 0.7 else None,
            input_tokens=random.randint(100, 5000),
            output_tokens=random.randint(50, 2000),
            total_tokens=random.randint(150, 7000),
            cost_usd=round(random.uniform(0.001, 0.05), 4),
            endpoint="/api/v1/ai/generate",
            client_ip=f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            user_agent="Mozilla/5.0 (Demo)",
            timestamp=datetime.now(tz=timezone.utc).replace(tzinfo=None) - timedelta(hours=random.randint(0, 168)),
        )
        logs.append(log)
        db.add(log)
    db.commit()
    return logs


def seed_alerts(db: Session, users: list, tools: list):
    """Create demo alerts."""
    alert_types = ["intrusion", "anomaly", "policy_violation", "threat_intel"]
    severities = ["low", "medium", "high", "critical"]
    statuses = ["open", "investigating", "resolved", "false_positive"]
    sources = ["blue_team", "threat_intel", "manual"]

    alerts = []
    for i in range(20):
        user = random.choice(users)
        tool = random.choice(tools)

        alert = Alert(
            title=random.choice(
                [
                    "Policy Violation Detected",
                    "Unauthorized Tool Access",
                    "Suspicious User Activity",
                    "Data Leak Attempt",
                    "Failed Login Attempt",
                    "Sensitive Data in Prompt",
                ]
            ),
            description=f"Demo alert {i}: triggered by user {user.email} using {tool.name}",
            alert_type=random.choice(alert_types),
            severity=random.choice(severities),
            status=random.choice(statuses),
            source=random.choice(sources),
            org_id=user.org_id,
            asset_id=None,
            mitre_tactic=random.choice(["TA0001", "TA0002", "TA0003", "TA0004"])
            if random.random() > 0.5
            else None,
            mitre_technique=random.choice(["T1190", "T1133", "T1200", "T1566"])
            if random.random() > 0.5
            else None,
            indicators={"demo": True, "tool": tool.name},
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None) - timedelta(hours=random.randint(0, 72)),
        )
        alerts.append(alert)
        db.add(alert)
    db.commit()
    return alerts


def seed_api_keys(db: Session, users: list):
    """Create demo API keys."""
    keys = []
    for user in users[:3]:
        api_key = APIKey(
            user_id=user.id,
            name=f"Demo Key - {user.department}",
            key_hash=f"sk_demo_{user.id}_{random.randint(1000, 9999)}",
            is_active=True,
            rate_limit_rpm=1000,
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None) - timedelta(days=random.randint(1, 30)),
            last_used=datetime.now(tz=timezone.utc).replace(tzinfo=None) - timedelta(hours=random.randint(0, 24)),
        )
        keys.append(api_key)
        db.add(api_key)
    db.commit()
    return keys


def seed_all(db: Session):
    """Seed all demo data."""
    existing_orgs = db.query(Organization).first()
    if existing_orgs:
        print("Clearing existing data for fresh seed...")
        db.query(AIUsageLog).delete()
        db.query(Alert).delete()
        db.query(APIKey).delete()
        db.query(Prompt).delete()
        db.query(Policy).delete()
        db.query(AITool).delete()
        db.query(User).delete()
        db.query(Organization).delete()
        db.commit()

    print("Seeding organizations...")
    print("Seeding organizations...")
    orgs = seed_organizations(db)

    print("Seeding users...")
    users = seed_users(db, orgs)

    print("Seeding AI tools...")
    tools = seed_ai_tools(db)

    print("Seeding policies...")
    policies = seed_policies(db, orgs, tools)

    print("Seeding prompts...")
    prompts = seed_prompts(db, orgs)

    print("Seeding audit logs...")
    audit_logs = seed_audit_logs(db, users, tools)

    print("Seeding alerts...")
    alerts = seed_alerts(db, users, tools)

    print("Seeding API keys...")
    api_keys = seed_api_keys(db, users)

    print("Seeding complete!")
    return {
        "organizations": len(orgs),
        "users": len(users),
        "tools": len(tools),
        "policies": len(policies),
        "prompts": len(prompts),
        "audit_logs": len(audit_logs),
        "alerts": len(alerts),
        "api_keys": len(api_keys),
    }


if __name__ == "__main__":
    from app.database import SessionLocal
    from app.models import Base
    from app.database import engine

    print("Creating tables...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        result = seed_all(db)
        print(f"\nSeed completed successfully!")
        print(f"Created: {result}")
    finally:
        db.close()
