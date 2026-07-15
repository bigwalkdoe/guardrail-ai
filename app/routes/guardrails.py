"""
Guardrail Evaluation Routes.
Endpoints for evaluating prompts and outputs against safety policies.
"""

import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.security import get_current_user, require_admin
from app.models import User, GuardrailRule
from app.services.guardrail_engine import GuardrailEngine
from app.schemas import (
    GuardrailEvaluateRequest,
    GuardrailEvaluateOutputRequest,
    GuardrailEvaluateResponse,
    GuardrailLogEntry,
    GuardrailStats,
    GuardrailRuleCreate,
    GuardrailRuleUpdate,
    GuardrailRuleResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/guardrails", tags=["guardrails"])


@router.post("/evaluate/prompt", response_model=GuardrailEvaluateResponse)
def evaluate_prompt(
    req: GuardrailEvaluateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Evaluate a prompt for injection, PII, and policy compliance."""
    engine = GuardrailEngine(db)
    result = engine.evaluate_prompt(
        prompt=req.prompt,
        user=current_user,
        tool_id=req.tool_id,
    )
    return result


@router.post("/evaluate/output", response_model=GuardrailEvaluateResponse)
def evaluate_output(
    req: GuardrailEvaluateOutputRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Evaluate LLM output for safety issues."""
    engine = GuardrailEngine(db)
    result = engine.evaluate_output(
        prompt=req.prompt,
        output=req.output,
        user=current_user,
    )
    return result


@router.get("/logs", response_model=List[GuardrailLogEntry])
def list_guardrail_logs(
    action: Optional[str] = Query(None, description="Filter by action (allow/warn/block)"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List guardrail evaluation logs."""
    engine = GuardrailEngine(db)
    org_id = current_user.org_id if current_user.role != "admin" else None
    filter_user_id = current_user.id if current_user.role != "admin" else user_id
    return engine.get_logs(
        org_id=org_id,
        action=action,
        user_id=filter_user_id,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=GuardrailStats)
def get_guardrail_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get guardrail evaluation statistics."""
    engine = GuardrailEngine(db)
    org_id = current_user.org_id if current_user.role != "admin" else None
    return engine.get_stats(org_id=org_id)


@router.get("/rules", response_model=List[GuardrailRuleResponse])
def list_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List guardrail rules."""
    query = db.query(GuardrailRule).filter(GuardrailRule.is_active == True)
    if current_user.role != "admin":
        query = query.filter(
            (GuardrailRule.org_id == current_user.org_id) | (GuardrailRule.org_id.is_(None))
        )
    rules = query.order_by(GuardrailRule.created_at.desc()).all()
    return [
        GuardrailRuleResponse(
            id=r.id,
            name=r.name,
            description=r.description,
            category=r.category,
            pattern=r.pattern,
            action=r.action,
            severity=r.severity,
            is_active=r.is_active,
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in rules
    ]


@router.post("/rules", response_model=GuardrailRuleResponse)
def create_rule(
    rule_data: GuardrailRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Create a custom guardrail rule."""
    import re
    try:
        re.compile(rule_data.pattern)
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")

    rule = GuardrailRule(
        org_id=current_user.org_id,
        name=rule_data.name,
        description=rule_data.description,
        category=rule_data.category,
        pattern=rule_data.pattern,
        action=rule_data.action,
        severity=rule_data.severity,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    return GuardrailRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        pattern=rule.pattern,
        action=rule.action,
        severity=rule.severity,
        is_active=rule.is_active,
        created_at=rule.created_at.isoformat() if rule.created_at else "",
    )


@router.put("/rules/{rule_id}", response_model=GuardrailRuleResponse)
def update_rule(
    rule_id: int,
    rule_data: GuardrailRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Update a guardrail rule."""
    rule = db.query(GuardrailRule).filter(GuardrailRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule_data.pattern:
        import re
        try:
            re.compile(rule_data.pattern)
        except re.error as e:
            raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")

    update_data = rule_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(rule, field, value)

    db.commit()
    db.refresh(rule)

    return GuardrailRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        pattern=rule.pattern,
        action=rule.action,
        severity=rule.severity,
        is_active=rule.is_active,
        created_at=rule.created_at.isoformat() if rule.created_at else "",
    )


@router.delete("/rules/{rule_id}")
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Delete a guardrail rule."""
    rule = db.query(GuardrailRule).filter(GuardrailRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    db.delete(rule)
    db.commit()
    return {"message": "Rule deleted successfully"}
