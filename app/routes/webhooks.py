"""
Webhook Management Routes.
Endpoints for creating, managing, and receiving webhooks.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import Optional, List
from pydantic import BaseModel

from app.database import get_db
from app.security import get_current_user
from app.models import User
from app.services.webhook_service import (
    WebhookService,
    WebhookEvent,
    verify_incoming_webhook,
    process_incoming_webhook,
)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class WebhookCreate(BaseModel):
    name: str
    url: str
    events: List[str]
    secret: Optional[str] = None
    timeout: int = 30
    retry_count: int = 3


class WebhookResponse(BaseModel):
    id: int
    name: str
    url: str
    events: List[str]
    status: str
    created_at: str


@router.post("/", response_model=WebhookResponse)
def create_webhook(
    webhook_data: WebhookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create new webhook."""
    service = WebhookService(db)

    for event in webhook_data.events:
        try:
            WebhookEvent(event)
        except:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event type: {event}",
            )

    result = service.create_webhook(
        user_id=current_user.id,
        name=webhook_data.name,
        url=webhook_data.url,
        events=webhook_data.events,
        secret=webhook_data.secret,
        timeout=webhook_data.timeout,
        retry_count=webhook_data.retry_count,
    )

    return result


@router.get("/", response_model=List[WebhookResponse])
def list_webhooks(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List webhooks."""
    service = WebhookService(db)

    user_id = current_user.id if current_user.role != "admin" else None
    return service.list_webhooks(user_id=user_id, status=status)


@router.delete("/{webhook_id}")
def delete_webhook(
    webhook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete webhook."""
    service = WebhookService(db)

    success = service.delete_webhook(webhook_id, current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return {"message": "Webhook deleted successfully"}


@router.post("/receive/{provider}")
async def receive_webhook(
    provider: str,
    request: Request,
):
    """Receive incoming webhook from external service.

    Supported providers: slack, github, generic
    """
    body = await request.body()
    headers = dict(request.headers)

    secret_setting = getattr(settings, f"{provider.upper()}_WEBHOOK_SECRET", None)
    if not secret_setting:
        secret_setting = settings.SLACK_WEBHOOK_URL or ""

    valid = verify_incoming_webhook(provider, body, headers, secret_setting)
    if not valid:
        logger.warning(f"Invalid webhook signature from {provider}")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    import json
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = {"raw": body.decode(errors="replace")}

    event = headers.get("X-GitHub-Event") or headers.get("X-Slack-Event") or payload.get("type", "unknown")
    result = process_incoming_webhook(provider, event, payload)

    # Slack URL verification challenge
    if provider == "slack" and payload.get("type") == "url_verification":
        return {"challenge": payload.get("challenge")}

    return result


@router.post("/{webhook_id}/test")
def test_webhook(
    webhook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Test webhook."""
    service = WebhookService(db)

    try:
        result = service.test_webhook(webhook_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
