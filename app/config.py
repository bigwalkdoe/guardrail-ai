"""
Production Configuration Module

This module handles all configuration management for the application.
Secrets and sensitive configuration should be loaded from environment variables
or external secrets management systems (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).

DO NOT commit secrets to version control. Use environment variables or
external secrets management systems.
"""

from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import Optional, List


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    APP_NAME: str = "Guardrail-AI"
    APP_ENV: str = "development"  # development, staging, production
    DEBUG: bool = False
    @field_validator("DEBUG", "FORCE_HTTPS", "SECURE_COOKIES", "SECURE_SSL_REDIRECT", mode="before")
    @classmethod
    def coerce_bool(cls, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() not in {"0", "false", "no", "off", "release", "disabled"}
        return bool(value)

    # Database
    DATABASE_URL: str
    POSTGRES_DB: Optional[str] = None
    POSTGRES_USER: Optional[str] = None
    POSTGRES_PASSWORD: Optional[str] = None

    # Database Pool Configuration
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 30
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    # Security
    SECRET_KEY: str
    ENCRYPTION_KEY: Optional[str] = None
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Cookie auth
    ACCESS_TOKEN_COOKIE: str = "access_token"
    REFRESH_TOKEN_COOKIE: str = "refresh_token"
    CSRF_COOKIE_NAME: str = "csrf_token"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"

    # CORS
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # Host Validation
    TRUSTED_HOSTS: str = "localhost,127.0.0.1,app"

    # Security - HTTPS
    FORCE_HTTPS: bool = False  # Set to True in production
    SECURE_COOKIES: bool = True  # Requires HTTPS
    SECURE_SSL_REDIRECT: bool = False  # Redirect HTTP to HTTPS

    # External API Keys (optional)
    API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    LOCAL_LLM_BASE_URL: Optional[str] = None

    # Alert Webhooks
    SLACK_WEBHOOK_URL: Optional[str] = None
    EMAIL_SMTP_SERVER: Optional[str] = None
    EMAIL_SMTP_PORT: Optional[int] = 587
    EMAIL_SMTP_USERNAME: Optional[str] = None
    EMAIL_SMTP_PASSWORD: Optional[str] = None
    EMAIL_FROM_ADDRESS: Optional[str] = None
    ALERT_EMAIL_RECIPIENTS: Optional[str] = None  # comma-separated emails

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json or text

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 10

    # IP Filtering
    IP_WHITELIST: Optional[str] = None
    IP_BLACKLIST: Optional[str] = None

    # Backup & Retention
    AUDIT_LOG_RETENTION_DAYS: int = 90
    BACKUP_DIR: str = "/backups"

    # Cache
    CACHE_TTL: int = 300  # 5 minutes
    CACHE_MAX_SIZE: int = 1000

    # Session
    SESSION_COOKIE_NAME: str = "session"
    REDIS_URL: Optional[str] = None
    SESSION_SECRET: Optional[str] = None
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "lax"

    # Redis (for caching and session management)
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None

    # Monitoring
    SENTRY_DSN: Optional[str] = None
    DATADOG_API_KEY: Optional[str] = None
    PROMETHEUS_ENABLED: bool = True

    # Background Tasks
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    # File Storage
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_REGION: str = "us-east-1"
    S3_BUCKET_NAME: Optional[str] = None

    # AWS CloudWatch Integration
    AWS_CLOUDWATCH_ENABLED: bool = False
    AWS_CLOUDWATCH_LOG_GROUP: str = "/aws/guardrail-ai"
    AWS_CLOUDWATCH_LOG_STREAM: str = "app-logs"
    AWS_CLOUDWATCH_BATCH_SIZE: int = 100
    AWS_CLOUDWATCH_BATCH_INTERVAL: int = 5

    # Google Chronicle Integration
    CHRONICLE_ENABLED: bool = False
    CHRONICLE_CUSTOMER_ID: Optional[str] = None
    CHRONICLE_API_KEY: Optional[str] = None
    CHRONICLE_REGION: str = "us"
    CHRONICLE_BATCH_SIZE: int = 50

    # PagerDuty Integration
    PAGERDUTY_ENABLED: bool = False
    PAGERDUTY_API_KEY: Optional[str] = None
    PAGERDUTY_ROUTING_KEY: Optional[str] = None
    PAGERDUTY_SERVICE_ID: Optional[str] = None
    PAGERDUTY_INTEGRATION_KEY: Optional[str] = None
    PAGERDUTY_RETRY_COUNT: int = 3
    PAGERDUTY_RETRY_INTERVAL: int = 5

    # LDAP/Active Directory Integration
    LDAP_ENABLED: bool = False
    LDAP_SERVER: Optional[str] = None
    LDAP_PORT: int = 389
    LDAP_USE_SSL: bool = False
    LDAP_USE_TLS: bool = False
    LDAP_BIND_DN: Optional[str] = None
    LDAP_BIND_PASSWORD: Optional[str] = None
    LDAP_BASE_DN: Optional[str] = None
    LDAP_USER_FILTER: str = "(sAMAccountName={username})"
    LDAP_GROUP_FILTER: str = "(member={user_dn})"
    LDAP_ATTR_USERNAME: str = "sAMAccountName"
    LDAP_ATTR_EMAIL: str = "mail"
    LDAP_ATTR_FIRST_NAME: str = "givenName"
    LDAP_ATTR_LAST_NAME: str = "sn"
    LDAP_ATTR_DISPLAY_NAME: str = "displayName"
    LDAP_ATTR_MEMBER_OF: str = "memberOf"
    LDAP_ATTR_ENABLED: str = "userAccountControl"
    LDAP_SEARCH_TIMEOUT: int = 30
    LDAP_AUTO_BIND: bool = True
    LDAP_AUTO_CREATE_USER: bool = False

    # HashiCorp Vault Integration
    VAULT_ENABLED: bool = False
    VAULT_ADDR: Optional[str] = None
    VAULT_TOKEN: Optional[str] = None
    VAULT_MOUNT_POINT: str = "secret"
    VAULT_KV_VERSION: int = 2
    VAULT_NAMESPACE: Optional[str] = None
    VAULT_CERT_PATH: Optional[str] = None
    VAULT_KEY_PATH: Optional[str] = None
    VAULT_CA_PATH: Optional[str] = None
    VAULT_TIMEOUT: int = 10

    # Email (optional)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: Optional[int] = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM_EMAIL: Optional[str] = None
    SMTP_TLS: bool = True

    # API Configuration
    API_V1_PREFIX: str = "/api/v1"
    DOCS_URL: str = "/docs"
    REDOC_URL: str = "/redoc"

    # Security Headers
    SECURITY_HEADERS_ENABLED: bool = True
    HSTS_MAX_AGE: int = 31536000  # 1 year

    # SAML/SSO Configuration
    SAML_ENABLED: bool = False
    SAML_IDP_ENTITY_ID: Optional[str] = None
    SAML_IDP_SSO_URL: Optional[str] = None
    SAML_IDP_SLO_URL: Optional[str] = None
    SAML_IDP_CERT: Optional[str] = None
    SAML_SP_ENTITY_ID: str = "guardrail-ai"
    SAML_SP_ACS_URL: Optional[str] = None
    SAML_SP_SLO_URL: Optional[str] = None
    SAML_NAME_ID_FORMAT: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    SAML_SIGN_METADATA: bool = False
    SAML_SIGN_ASSERTION: bool = True
    SAML_ENCRYPT_ASSERTION: bool = False
    SAML_ATTR_EMAIL: str = "email"
    SAML_ATTR_FIRST_NAME: str = "firstName"
    SAML_ATTR_LAST_NAME: str = "lastName"
    SAML_ATTR_ROLE: str = "role"

    # SIEM Integration - Splunk
    SIEM_SPLUNK_ENABLED: bool = False
    SIEM_SPLUNK_HEC_URL: Optional[str] = None
    SIEM_SPLUNK_HEC_TOKEN: Optional[str] = None
    SIEM_SPLUNK_INDEX: str = "main"
    SIEM_SPLUNK_SOURCE: str = "guardrail-ai"
    SIEM_SPLUNK_SOURCETYPE: str = "guardrail:security"
    SIEM_SPLUNK_VERIFY_SSL: bool = True

    # SIEM Integration - QRadar
    SIEM_QRADAR_ENABLED: bool = False
    SIEM_QRADAR_HOST: Optional[str] = None
    SIEM_QRADAR_PORT: int = 514
    SIEM_QRADAR_PROTOCOL: str = "tcp"
    SIEM_QRADAR_LOG_SOURCE_ID: Optional[str] = None

    # SIEM Integration - ArcSight
    SIEM_ARCSIGHT_ENABLED: bool = False
    SIEM_ARCSIGHT_HOST: Optional[str] = None
    SIEM_ARCSIGHT_PORT: int = 514
    SIEM_ARCSIGHT_CERT: Optional[str] = None
    SIEM_ARCSIGHT_KEY: Optional[str] = None

    # SIEM Integration - Syslog
    SIEM_SYSLOG_ENABLED: bool = False
    SIEM_SYSLOG_HOST: Optional[str] = None
    SIEM_SYSLOG_PORT: int = 514
    SIEM_SYSLOG_PROTOCOL: str = "udp"
    SIEM_SYSLOG_FACILITY: str = "local0"
    SIEM_SYSLOG_FORMAT: str = "rfc5424"

    # SIEM Integration - Elasticsearch
    SIEM_ELASTIC_ENABLED: bool = False
    SIEM_ELASTIC_URL: Optional[str] = None
    SIEM_ELASTIC_API_KEY: Optional[str] = None
    SIEM_ELASTIC_INDEX_PREFIX: str = "guardrail-"
    SIEM_ELASTIC_INDEX_SUFFIX: str = "events"
    SIEM_ELASTIC_VERIFY_SSL: bool = True

    # SIEM Integration - Azure Sentinel
    SIEM_AZURE_SENTINEL_ENABLED: bool = False
    SIEM_AZURE_WORKSPACE_ID: Optional[str] = None
    SIEM_AZURE_SHARED_KEY: Optional[str] = None
    SIEM_AZURE_LOG_TYPE: str = "GuardrailAI"

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "forbid"  # Reject unknown fields to catch config typos

    @property
    def allowed_origins_list(self) -> List[str]:
        """Parse ALLOWED_ORIGINS string into list."""
        return [
            origin.strip()
            for origin in self.ALLOWED_ORIGINS.split(",")
            if origin.strip()
        ]

    @property
    def trusted_hosts_list(self) -> List[str]:
        """Parse TRUSTED_HOSTS string into list."""
        return [host.strip() for host in self.TRUSTED_HOSTS.split(",") if host.strip()]

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.APP_ENV.lower() == "production"

    @property
    def is_staging(self) -> bool:
        """Check if running in staging mode."""
        return self.APP_ENV.lower() == "staging"

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.APP_ENV.lower() == "development"


def get_settings() -> Settings:
    """
    Get application settings.

    In production, this should integrate with:
    - HashiCorp Vault
    - AWS Secrets Manager
    - Azure Key Vault
    - Kubernetes Secrets

    Priority order:
    1. Environment variables (highest priority)
    2. External secrets management (production)
    3. .env file (development)
    """
    # In production, you would integrate with external secrets management here
    # For example, using hvac library for Vault:
    #
    # if os.getenv("APP_ENV") == "production":
    #     import hvac
    #     client = hvac.Client(url=os.getenv("VAULT_ADDR"), token=os.getenv("VAULT_TOKEN"))
    #     secrets = client.secrets.kv.v2.read_secret_path(path="guardrail-ai")
    #     # Override environment variables with secrets from Vault

    return Settings()


# Global settings instance
settings = get_settings()
