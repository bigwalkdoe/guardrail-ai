import base64
import hashlib
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode, quote
import xml.etree.ElementTree as ET

import requests
from lxml import etree
from sqlalchemy.orm import Session

from app.config import settings
from app.models import User, Organization

logger = logging.getLogger(__name__)

# Optional SAML imports - provide stubs if python3-saml is not installed
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    SAML_AVAILABLE = True
except ImportError:
    logger.warning("python3-saml not installed; SAML/SSO features disabled")
    SAML_AVAILABLE = False
    
    class _SAMLStub:
        def __init__(self, *args, **kwargs):
            raise ImportError("SAML authentication requires python3-saml package. Install with: pip install python3-saml")
        
        def __getattr__(self, name):
            raise ImportError("SAML authentication requires python3-saml package. Install with: pip install python3-saml")
    
    OneLogin_Saml2_Auth = _SAMLStub
    OneLogin_Saml2_Settings = _SAMLStub
    OneLogin_Saml2_Utils = _SAMLStub
    SAML_AVAILABLE = False

logger = logging.getLogger(__name__)

class SAMLAuthError(Exception):
    """SAML authentication error."""
    pass

class SAMLConfig:
    """SAML configuration manager."""
    
    def __init__(self, db: Session):
        self.db = db
        
    @staticmethod
    def get_idp_metadata() -> Dict[str, Any]:
        """Get Identity Provider metadata from settings."""
        return {
            "entity_id": getattr(settings, "SAML_IDP_ENTITY_ID", ""),
            "sso_url": getattr(settings, "SAML_IDP_SSO_URL", ""),
            "slo_url": getattr(settings, "SAML_IDP_SLO_URL", ""),
            "x509_cert": getattr(settings, "SAML_IDP_CERT", ""),
            "attr_mapping": {
                "email": getattr(settings, "SAML_ATTR_EMAIL", "email"),
                "first_name": getattr(settings, "SAML_ATTR_FIRST_NAME", "firstName"),
                "last_name": getattr(settings, "SAML_ATTR_LAST_NAME", "lastName"),
                "role": getattr(settings, "SAML_ATTR_ROLE", "role"),
            },
        }
    
    @staticmethod
    def get_sp_config() -> Dict[str, Any]:
        """Get Service Provider configuration."""
        return {
            "entity_id": getattr(settings, "SAML_SP_ENTITY_ID", "guardrail-ai"),
            "acs_url": getattr(settings, "SAML_SP_ACS_URL", ""),
            "slo_url": getattr(settings, "SAML_SP_SLO_URL", ""),
            "name_id_format": getattr(
                settings,
                "SAML_NAME_ID_FORMAT",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            ),
            "sign_metadata": getattr(settings, "SAML_SIGN_METADATA", False),
            "sign_assertion": getattr(settings, "SAML_SIGN_ASSERTION", True),
            "encrypt_assertion": getattr(settings, "SAML_ENCRYPT_ASSERTION", False),
        }
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate SAML configuration."""
        idp = self.get_idp_metadata()
        sp = self.get_sp_config()
        
        errors = []
        if not idp.get("entity_id"):
            errors.append("SAML_IDP_ENTITY_ID not configured")
        if not idp.get("sso_url"):
            errors.append("SAML_IDP_SSO_URL not configured")
        if not idp.get("x509_cert"):
            errors.append("SAML_IDP_CERT not configured")
        if not sp.get("acs_url"):
            errors.append("SAML_SP_ACS_URL not configured")
        
        return {"valid": len(errors) == 0, "errors": errors}


class SAMLService:
    """SAML 2.0 authentication service."""
    
    def __init__(self, db: Session):
        self.db = db
        self.config = SAMLConfig(db)
    
    def _get_saml_auth(self, request_data: Dict[str, Any]) -> "OneLogin_Saml2_Auth":
        """Create SAML auth object from request data."""
        if not SAML_AVAILABLE:
            raise ImportError("SAML authentication requires python3-saml package. Install with: pip install python3-saml")
        
        settings = OneLogin_Saml2_Settings(
            self.config.get_sp_config(),
            sp_validation_only=True
        )
        return OneLogin_Saml2_Auth(request_data, settings)
    
    def init_sso(self, request_data: Dict[str, Any], return_to: Optional[str] = None) -> str:
        """Initialize SAML SSO and return redirect URL."""
        if not SAML_AVAILABLE:
            raise ImportError("SAML authentication requires python3-saml package. Install with: pip install python3-saml")
        
        auth = self._get_saml_auth(request_data)
        if return_to:
            auth.login(return_to=return_to)
        else:
            auth.login()
        return auth.get_sso_url()
    
    def process_sso(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process SAML SSO response."""
        if not SAML_AVAILABLE:
            raise ImportError("SAML authentication requires python3-saml package. Install with: pip install python3-saml")
        
        auth = self._get_saml_auth(request_data)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            raise SAMLAuthError(f"SAML response errors: {errors}")
        
        if not auth.is_authenticated():
            raise SAMLAuthError("SAML authentication failed")
        
        attributes = auth.get_attributes()
        name_id = auth.get_nameid()
        
        return {
            "name_id": name_id,
            "attributes": attributes,
            "session_index": auth.get_session_index(),
        }
    
    def init_slo(self, request_data: Dict[str, Any], name_id: str, session_index: str) -> str:
        """Initialize SAML Single Logout."""
        if not SAML_AVAILABLE:
            raise ImportError("SAML authentication requires python3-saml package. Install with: pip install python3-saml")
        
        auth = self._get_saml_auth(request_data)
        auth.logout(name_id=name_id, session_index=session_index)
        return auth.get_slo_url()
    
    def process_slo(self, request_data: Dict[str, Any]) -> bool:
        """Process SAML Single Logout response."""
        if not SAML_AVAILABLE:
            raise ImportError("SAML authentication requires python3-saml package. Install with: pip install python3-saml")
        
        auth = self._get_saml_auth(request_data)
        auth.process_slo()
        return not auth.get_errors()
    
    def get_metadata(self) -> str:
        """Get SP metadata XML."""
        if not SAML_AVAILABLE:
            raise ImportError("SAML authentication requires python3-saml package. Install with: pip install python3-saml")
        
        settings = OneLogin_Saml2_Settings(self.config.get_sp_config(), sp_validation_only=True)
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        if errors:
            raise SAMLAuthError(f"Invalid SP metadata: {errors}")
        return metadata
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate SAML configuration."""
        return self.config.validate_config()


def create_saml_request(request: Any) -> Dict[str, Any]:
    """Extract SAML request data from FastAPI request."""
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.url.hostname,
        "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": {},
    }
