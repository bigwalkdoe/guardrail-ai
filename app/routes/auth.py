"""
Authentication Routes.
Handles user authentication including SAML/SSO login.
"""

import logging
from datetime import timedelta
from typing import Optional
import secrets
import string
import redis

logger = logging.getLogger(__name__)
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import User
from app.schemas import Token, UserCreate, UserResponse
from app.security import (
    create_access_token,
    create_refresh_token,
    set_auth_cookies,
    get_current_user,
    generate_csrf_token,
    hash_password,
    verify_password,
)

# SAML is optional - import lazily to avoid hard dependency at module load
SAMLService = None
SAMLAuthError = None

def _get_saml_service():
    """Lazily import SAML service to allow running without python3-saml."""
    global SAMLService, SAMLAuthError
    if SAMLService is None:
        try:
            from app.services.saml_service import SAMLService as _SAMLService, SAMLAuthError as _SAMLAuthError
            SAMLService = _SAMLService
            SAMLAuthError = _SAMLAuthError
        except ImportError as e:
            # Create a stub class that raises a clear error when used
            class _SAMLAuthError(Exception):
                pass
            class _SAMLService:
                def __init__(self, *args, **kwargs):
                    raise ImportError("SAML authentication requires python3-saml package. Install with: pip install python3-saml")
            SAMLAuthError = _SAMLAuthError
            SAMLService = _SAMLService
    return SAMLService

router = APIRouter(prefix="/auth", tags=["authentication"])

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


def get_redis_client():
    """Get Redis client for rate limiting."""
    if not settings.REDIS_URL:
        logger.warning("REDIS_URL not configured — auth rate limiting and lockout disabled")
        return None
    try:
        return redis.from_url(settings.REDIS_URL)
    except Exception as e:
        logger.warning(f"Redis connection failed — auth rate limiting and lockout disabled: {e}")
        return None


def check_account_lockout(email: str) -> Optional[int]:
    """Check if account is locked out. Returns remaining lockout seconds or None."""
    redis_client = get_redis_client()
    if not redis_client:
        return None

    lock_key = f"lockout:{email}"
    remaining = redis_client.ttl(lock_key)
    if remaining > 0:
        return remaining
    return None


def increment_failed_attempts(email: str) -> int:
    """Increment failed login attempts. Returns total failed attempts."""
    redis_client = get_redis_client()
    if not redis_client:
        return 0

    key = f"failed_login:{email}"
    attempts = redis_client.incr(key)
    redis_client.expire(key, 300)  # 5 minute window
    return attempts


def clear_failed_attempts(email: str):
    """Clear failed login attempts on successful login."""
    redis_client = get_redis_client()
    if redis_client:
        redis_client.delete(f"failed_login:{email}")


def lockout_account(email: str):
    """Lock account after max failed attempts."""
    redis_client = get_redis_client()
    if redis_client:
        redis_client.setex(f"lockout:{email}", LOCKOUT_DURATION_MINUTES * 60, "1")


@router.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""
    existing = db.query(User).filter(User.email == user_data.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Registration failed"
        )

    try:
        hashed = hash_password(user_data.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        )

    user = User(
        email=user_data.email,
        hashed_password=hashed,
        role=user_data.role or "employee",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return user


from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login", response_model=Token)
def login(
    request: Request,
    response: Response,
    login_data: LoginRequest = None,
    db: Session = Depends(get_db),
):
    if login_data is None:
        login_data = LoginRequest(email="", password="")
    
    email = login_data.email
    password = login_data.password

    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.hashed_password):
        attempts = increment_failed_attempts(email)
        remaining = check_account_lockout(email)
        if remaining:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account locked. Try again in {remaining} seconds",
                headers={"WWW-Authenticate": "Bearer", "Retry-After": str(remaining)},
            )
        if attempts >= MAX_LOGIN_ATTEMPTS:
            lockout_account(email)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to too many failed attempts",
                headers={"WWW-Authenticate": "Bearer"},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
        )

    csrf_token = generate_csrf_token()
    access_token = create_access_token(data={"sub": user.email, "user_id": user.id, "role": user.role})
    refresh_token = create_refresh_token(data={"sub": user.email, "user_id": user.id})

    clear_failed_attempts(email)
    set_auth_cookies(response, access_token, refresh_token, csrf_token=csrf_token)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        csrf_token=csrf_token,
    )


@router.post("/logout")
def logout(response: Response):
    """Logout user by clearing auth cookies."""
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    return current_user


@router.post("/refresh", response_model=Token)
def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    """Refresh access token using refresh token from cookie."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not provided",
        )

    try:
        from app.security import decode_token
        payload = decode_token(refresh_token, expected_type="refresh")
        email = payload.get("sub")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    csrf_token = generate_csrf_token()
    new_access_token = create_access_token(data={"sub": user.email, "user_id": user.id, "role": user.role})
    new_refresh_token = create_refresh_token(data={"sub": user.email, "user_id": user.id})
    set_auth_cookies(response, new_access_token, new_refresh_token, csrf_token=csrf_token)

    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        csrf_token=csrf_token,
    )


# SAML/SSO Routes (optional - only available if python3-saml is installed)

def _saml_service(db: Session):
    """Get SAML service instance, raising clear error if not available."""
    svc_cls = _get_saml_service()
    return svc_cls(db)


@router.get("/saml/metadata")
def saml_metadata():
    """Get SAML Service Provider metadata XML."""
    try:
        # Create a minimal service instance just for metadata
        class _MockDB:
            pass
        svc = _get_saml_service()(_MockDB())
        metadata = svc.get_metadata()
        from fastapi.responses import Response
        return Response(content=metadata, media_type="application/xml")
    except ImportError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SAML metadata error: {str(e)}")


@router.get("/saml/login")
def saml_login(request: Request, return_to: Optional[str] = None):
    """Initiate SAML SSO login."""
    try:
        svc = _saml_service(None)  # DB not needed for init
        request_data = {
            "https": "on" if request.url.scheme == "https" else "off",
            "http_host": request.url.hostname,
            "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
            "script_name": request.url.path,
            "get_data": dict(request.query_params),
            "post_data": {},
        }
        return RedirectResponse(url=svc.init_sso(request_data, return_to))
    except ImportError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SAML login error: {str(e)}")


@router.post("/saml/acs")
async def saml_acs(request: Request, response: Response, db: Session = Depends(get_db)):
    """Assertion Consumer Service - process SAML response."""
    try:
        svc = _saml_service(db)
        form_data = {}
        if request.method == "POST":
            form_data = await request.form()
        request_data = {
            "https": "on" if request.url.scheme == "https" else "off",
            "http_host": request.url.hostname,
            "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
            "script_name": request.url.path,
            "get_data": dict(request.query_params),
            "post_data": form_data,
        }
        saml_result = svc.process_sso(request_data)
        
        # Find or create user
        email = saml_result.get("attributes", {}).get("email", [None])[0] if isinstance(saml_result.get("attributes", {}).get("email"), list) else saml_result.get("attributes", {}).get("email")
        if not email:
            raise HTTPException(status_code=400, detail="SAML response missing email attribute")
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                email=email,
                hashed_password="",  # No password for SAML users
                role="employee",
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        
        if not user.is_active:
            raise HTTPException(status_code=401, detail="Account disabled")
        
        csrf_token = generate_csrf_token()
        access_token = create_access_token(data={"sub": user.email, "user_id": user.id, "role": user.role})
        refresh_token = create_refresh_token(data={"sub": user.email, "user_id": user.id})
        set_auth_cookies(response, access_token, refresh_token, csrf_token=csrf_token)
        
        return RedirectResponse(url="/", status_code=302)
    except ImportError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SAML ACS error: {str(e)}")


@router.get("/saml/slo")
def saml_slo(request: Request):
    """Initiate SAML Single Logout."""
    try:
        svc = _saml_service(None)
        name_id = request.query_params.get("name_id")
        session_index = request.query_params.get("session_index")
        if not name_id or not session_index:
            raise HTTPException(status_code=400, detail="Missing name_id or session_index")
        
        request_data = {
            "https": "on" if request.url.scheme == "https" else "off",
            "http_host": request.url.hostname,
            "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
            "script_name": request.url.path,
            "get_data": dict(request.query_params),
            "post_data": {},
        }
        logout_url = svc.init_slo(request_data, name_id, session_index)
        return RedirectResponse(url=logout_url)
    except ImportError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SAML SLO error: {str(e)}")


@router.post("/saml/sls")
async def saml_sls(request: Request, response: Response):
    """Process SAML Single Logout response."""
    try:
        svc = _saml_service(None)
        form_data = await request.form()
        request_data = {
            "https": "on" if request.url.scheme == "https" else "off",
            "http_host": request.url.hostname,
            "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
            "script_name": request.url.path,
            "get_data": dict(request.query_params),
            "post_data": dict(form_data),
        }
        success = svc.process_slo(request_data)
        if success:
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            return RedirectResponse(url="/")
        else:
            raise HTTPException(status_code=400, detail="SAML logout failed")
    except ImportError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SAML SLS error: {str(e)}")
