import bcrypt
import hashlib
import hmac
import secrets
import re
from datetime import datetime, timezone, timedelta, timezone
from typing import Optional, Dict, Any
import logging
from ipaddress import ip_address, ip_network

from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import uuid

from app.config import settings
from app.database import get_db
from app.models import User as UserModel, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

# Enterprise Security Constants
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=15)
SESSION_TIMEOUT = timedelta(hours=8)
PASSWORD_HISTORY_SIZE = 5

# Security Patterns
PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,128}$'
)
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Initialize encryption
def get_encryption_key() -> bytes:
    """Get encryption key from environment.
    In production, ENCRYPTION_KEY must be set explicitly.
    In development, a warning is emitted and a derived key is used."""
    key = getattr(settings, 'ENCRYPTION_KEY', None)
    if not key:
        if settings.is_production:
            raise RuntimeError(
                "ENCRYPTION_KEY is not set. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        logger.warning(
            "ENCRYPTION_KEY not set — using derived key (INSECURE: development only). "
            "Set ENCRYPTION_KEY in production."
        )
        salt = b'guardrail_salt_2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(b'guardrail_encryption_key'))
    if isinstance(key, str):
        key = key.encode()
    return key

encryption_fernet = Fernet(get_encryption_key())

logger = logging.getLogger(__name__)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password strength against enterprise requirements."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"

    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must be no more than {MAX_PASSWORD_LENGTH} characters long"

    if not PASSWORD_PATTERN.match(password):
        return False, "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"

    normalized = password.lower()
    weak_passwords = ['password', '123456', 'qwerty', 'admin', 'password123', 'guardrail']
    if normalized in weak_passwords:
        return False, "Password is too common, please choose a stronger password"

    for i in range(len(password) - 2):
        chunk = password[i:i+3]
        if chunk.isdigit():
            a, b, c = int(chunk[0]), int(chunk[1]), int(chunk[2])
            if (b == a + 1 and c == b + 1) or (b == a - 1 and c == b - 1):
                return False, "Password contains sequential numbers"

    return True, "Password is valid"


def hash_password(password: str) -> str:
    """Hash a password using enterprise-grade bcrypt settings."""
    # Validate password before hashing
    is_valid, error_msg = validate_password_strength(password)
    if not is_valid:
        raise ValueError(f"Password validation failed: {error_msg}")

    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode(
        "utf-8"
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash with timing attack protection."""
    try:
        # Use constant-time comparison
        return hmac.compare_digest(
            bcrypt.hashpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8")),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def encrypt_sensitive_data(data: str) -> str:
    """Encrypt sensitive data using Fernet encryption."""
    return encryption_fernet.encrypt(data.encode()).decode()


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """Decrypt sensitive data."""
    return encryption_fernet.decrypt(encrypted_data.encode()).decode()


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure token."""
    return secrets.token_urlsafe(length)


def validate_email_format(email: str) -> bool:
    """Validate email format and prevent common attacks."""
    if not email or len(email) > 254:  # RFC 5321 limit
        return False
    return bool(EMAIL_PATTERN.match(email))


def check_ip_allowlist(client_ip: str, allowlist: list = None) -> bool:
    """Check if client IP is in allowlist."""
    if not allowlist:
        return True

    try:
        client_addr = ip_address(client_ip)
        return any(client_addr in ip_network(net) for net in allowlist)
    except ValueError:
        return False


def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """Sanitize user input to prevent injection attacks."""
    if not input_str:
        return ""

    # Remove null bytes and other dangerous characters
    sanitized = input_str.replace('\x00', '').replace('\r\n', '\n').replace('\r', '\n')

    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized.strip()


def _get_token_from_request(request: Request, header_token: str | None) -> str:
    cookie_token = request.cookies.get(settings.ACCESS_TOKEN_COOKIE)
    if cookie_token:
        return cookie_token
    if header_token:
        return header_token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> UserModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        raw_token = _get_token_from_request(request, token)
        payload = decode_token(raw_token, expected_type="access")
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except HTTPException:
        raise
    except Exception:
        raise credentials_exception

    user = db.query(UserModel).filter(UserModel.email == email).first()
    if user is None:
        raise credentials_exception
    return user


def require_admin(
    current_user: UserModel = Depends(get_current_user),
) -> UserModel:
    if current_user.role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def require_admin_or_auditor(
    current_user: UserModel = Depends(get_current_user),
) -> UserModel:
    if current_user.role not in {UserRole.ADMIN.value, UserRole.AUDITOR.value}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or auditor access required",
        )
    return current_user


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def api_key_prefix(raw_key: str, length: int = 8) -> str:
    return raw_key[:length]


def create_access_token(
    subject: str | None = None,
    expires_delta: timedelta | None = None,
    *,
    data: dict | None = None,
) -> str:
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode: dict = {}
    if subject:
        to_encode["sub"] = subject
    if data:
        to_encode.update(data)
    if "sub" not in to_encode:
        raise ValueError("subject or data['sub'] is required")
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    to_encode["exp"] = now + expires_delta
    to_encode["iat"] = now
    to_encode["jti"] = str(uuid.uuid4())
    to_encode["typ"] = "access"
    to_encode["aud"] = settings.APP_NAME
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(
    subject: str | None = None,
    expires_delta: timedelta | None = None,
    *,
    data: dict | None = None,
) -> str:
    if expires_delta is None:
        expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode: dict = {}
    if subject:
        to_encode["sub"] = subject
    if data:
        to_encode.update(data)
    if "sub" not in to_encode:
        raise ValueError("subject or data['sub'] is required")
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    to_encode["exp"] = now + expires_delta
    to_encode["iat"] = now
    to_encode["jti"] = str(uuid.uuid4())
    to_encode["typ"] = "refresh"
    to_encode["aud"] = settings.APP_NAME
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str, expected_type: str | None = None) -> dict:
    """Decode and validate a JWT token, optionally checking its type."""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
            audience=settings.APP_NAME,
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
        )
    if expected_type and payload.get("typ") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Expected {expected_type} token, got {payload.get('typ', 'unknown')}",
        )
    return payload


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: str | None = None,
) -> None:
    access_max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60

    response.set_cookie(
        settings.ACCESS_TOKEN_COOKIE,
        access_token,
        max_age=access_max_age,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        path="/",
    )
    response.set_cookie(
        settings.REFRESH_TOKEN_COOKIE,
        refresh_token,
        max_age=refresh_max_age,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        path="/",
    )
    if csrf_token is not None:
        response.set_cookie(
            settings.CSRF_COOKIE_NAME,
            csrf_token,
            max_age=refresh_max_age,
            httponly=False,
            secure=settings.SESSION_COOKIE_SECURE,
            samesite=settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(settings.ACCESS_TOKEN_COOKIE, path="/")
    response.delete_cookie(settings.REFRESH_TOKEN_COOKIE, path="/")
    response.delete_cookie(settings.CSRF_COOKIE_NAME, path="/")
