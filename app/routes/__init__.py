"""
Routes module - exports all route modules for easy importing.
"""

from . import auth
from . import reporting
from . import security
from . import integrations
from . import health
from . import users
from . import audit
from . import api_keys
from . import webhooks
from . import playbooks
from . import inventory
from . import policies
from . import incidents
from . import config_scanner
from . import network

__all__ = [
    "auth",
    "reporting",
    "security",
    "integrations",
    "health",
    "users",
    "audit",
    "api_keys",
    "webhooks",
    "playbooks",
    "inventory",
    "policies",
    "incidents",
    "config_scanner",
    "network",
]
