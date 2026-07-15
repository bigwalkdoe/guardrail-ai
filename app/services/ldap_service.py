"""
LDAP/Active Directory Integration Service.
Provides integration with LDAP/AD for authentication and user management.
"""

import logging
import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

import ldap3
from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException, LDAPBindError

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class LDAPUser:
    """LDAP user data."""

    username: str = ""
    dn: str = ""
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    display_name: str = ""
    groups: List[str] = None
    enabled: bool = True
    raw_attributes: Dict[str, Any] = None

    def __post_init__(self):
        if self.groups is None:
            self.groups = []
        if self.raw_attributes is None:
            self.raw_attributes = {}


class LDAPConfig:
    """LDAP/AD configuration manager."""

    @staticmethod
    def get_config() -> Dict[str, Any]:
        """Get LDAP configuration."""
        return {
            "enabled": getattr(settings, "LDAP_ENABLED", False),
            "server": getattr(settings, "LDAP_SERVER", ""),
            "port": getattr(settings, "LDAP_PORT", 389),
            "use_ssl": getattr(settings, "LDAP_USE_SSL", False),
            "use_tls": getattr(settings, "LDAP_USE_TLS", False),
            "bind_dn": getattr(settings, "LDAP_BIND_DN", ""),
            "bind_password": getattr(settings, "LDAP_BIND_PASSWORD", ""),
            "base_dn": getattr(settings, "LDAP_BASE_DN", ""),
            "user_filter": getattr(
                settings, "LDAP_USER_FILTER", "(sAMAccountName={username})"
            ),
            "group_filter": getattr(
                settings, "LDAP_GROUP_FILTER", "(member={user_dn})"
            ),
            "attr_username": getattr(settings, "LDAP_ATTR_USERNAME", "sAMAccountName"),
            "attr_email": getattr(settings, "LDAP_ATTR_EMAIL", "mail"),
            "attr_first_name": getattr(settings, "LDAP_ATTR_FIRST_NAME", "givenName"),
            "attr_last_name": getattr(settings, "LDAP_ATTR_LAST_NAME", "sn"),
            "attr_display_name": getattr(
                settings, "LDAP_ATTR_DISPLAY_NAME", "displayName"
            ),
            "attr_member_of": getattr(settings, "LDAP_ATTR_MEMBER_OF", "memberOf"),
            "attr_enabled": getattr(
                settings, "LDAP_ATTR_ENABLED", "userAccountControl"
            ),
            "search_timeout": getattr(settings, "LDAP_SEARCH_TIMEOUT", 30),
            "auto_bind": getattr(settings, "LDAP_AUTO_BIND", True),
        }


class LDAPClient:
    """LDAP/AD client."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.server = None
        self.connection = None
        self._connected = False

        if config.get("enabled"):
            self._connect()

    def _connect(self):
        """Connect to LDAP server."""
        try:
            server_uri = f"{'ldap://' if not self.config.get('use_ssl') else 'ldaps://'}{self.config.get('server')}:{self.config.get('port')}"

            self.server = Server(
                server_uri,
                use_ssl=self.config.get("use_ssl", False),
                get_info=ldap3.ALL,
            )

            if self.config.get("auto_bind") and self.config.get("bind_dn"):
                self.connection = Connection(
                    self.server,
                    self.config.get("bind_dn"),
                    self.config.get("bind_password"),
                    auto_bind=True,
                    receive_timeout=self.config.get("search_timeout", 30),
                )
                self._connected = True
                logger.info(f"Connected to LDAP server: {self.config.get('server')}")
            else:
                self._connected = True
        except LDAPBindError as e:
            logger.error(f"LDAP bind failed: {e}")
            self._connected = False
        except LDAPException as e:
            logger.error(f"LDAP connection error: {e}")
            self._connected = False

    def _build_user_filter(self, username: str) -> str:
        """Build user search filter."""
        template = self.config.get("user_filter", "(sAMAccountName={username})")
        return template.replace("{username}", username)

    def _parse_user_attributes(self, entry: ldap3.Entry) -> LDAPUser:
        """Parse LDAP entry to LDAPUser."""
        attrs = self.config
        raw_attrs = entry.entry_attributes_as_dict

        username = str(getattr(entry, attrs.get("attr_username", "sAMAccountName"), ""))
        email = str(getattr(entry, attrs.get("attr_email", "mail"), ""))
        first_name = str(getattr(entry, attrs.get("attr_first_name", "givenName"), ""))
        last_name = str(getattr(entry, attrs.get("attr_last_name", "sn"), ""))
        display_name = str(
            getattr(entry, attrs.get("attr_display_name", "displayName"), "")
        )

        groups = []
        if attrs.get("attr_member_of") in raw_attrs:
            for group_dn in raw_attrs[attrs.get("attr_member_of")]:
                group_cn = group_dn.split(",")[0].replace("CN=", "")
                groups.append(group_cn)

        enabled = True
        if attrs.get("attr_enabled") in raw_attrs:
            user_control = raw_attrs[attrs.get("attr_enabled")][0]
            enabled = not (user_control & 2)

        return LDAPUser(
            username=username,
            dn=entry.entry_dn,
            email=email,
            first_name=first_name,
            last_name=last_name,
            display_name=display_name,
            groups=groups,
            enabled=enabled,
            raw_attributes=raw_attrs,
        )

    def authenticate(self, username: str, password: str) -> Optional[LDAPUser]:
        """Authenticate user against LDAP."""
        if not self._connected or not password:
            return None

        try:
            user_filter = self._build_user_filter(username)
            base_dn = self.config.get("base_dn")

            conn = Connection(
                self.server,
                user=f"{self.config.get('bind_dn')}",
                password=self.config.get("bind_password"),
                auto_bind=True,
            )

            conn.search(
                search_base=base_dn,
                search_filter=user_filter,
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
            )

            if conn.entries:
                entry = conn.entries[0]
                user_dn = entry.entry_dn

                auth_conn = Connection(self.server, user_dn, password, auto_bind=True)

                if auth_conn.bound:
                    user = self._parse_user_attributes(entry)
                    auth_conn.unbind()
                    conn.unbind()
                    return user

            conn.unbind()
        except LDAPBindError:
            logger.warning(f"LDAP authentication failed for: {username}")
        except LDAPException as e:
            logger.error(f"LDAP auth error: {e}")

        return None

    def search_user(self, username: str) -> Optional[LDAPUser]:
        """Search for user in LDAP."""
        if not self._connected:
            return None

        try:
            user_filter = self._build_user_filter(username)
            base_dn = self.config.get("base_dn")

            self.connection.search(
                search_base=base_dn,
                search_filter=user_filter,
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
            )

            if self.connection.entries:
                return self._parse_user_attributes(self.connection.entries[0])
        except LDAPException as e:
            logger.error(f"LDAP search error: {e}")

        return None

    def search_users(self, filter: str = "", limit: int = 100) -> List[LDAPUser]:
        """Search for users in LDAP."""
        if not self._connected:
            return []

        users = []
        try:
            search_filter = filter or self.config.get(
                "user_filter", "(objectClass=user)"
            ).replace("{username}", "*")
            base_dn = self.config.get("base_dn")

            self.connection.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
                size_limit=limit,
            )

            for entry in self.connection.entries:
                users.append(self._parse_user_attributes(entry))
        except LDAPException as e:
            logger.error(f"LDAP search error: {e}")

        return users

    def get_user_groups(self, username: str) -> List[str]:
        """Get user's groups."""
        user = self.search_user(username)
        return user.groups if user else []

    def is_member_of(self, username: str, group: str) -> bool:
        """Check if user is member of group."""
        groups = self.get_user_groups(username)
        return group in groups

    def unbind(self):
        """Unbind from LDAP server."""
        if self.connection:
            self.connection.unbind()
        self._connected = False


class LDAPService:
    """Main LDAP/AD integration service."""

    def __init__(self):
        self.config = LDAPConfig.get_config()
        self.client: Optional[LDAPClient] = None

        if self.config.get("enabled"):
            if self.config.get("server") and self.config.get("base_dn"):
                self.client = LDAPClient(self.config)
            else:
                logger.warning("LDAP enabled but missing server or base DN")

    def authenticate(self, username: str, password: str) -> Optional[LDAPUser]:
        """Authenticate user."""
        if self.client:
            return self.client.authenticate(username, password)
        return None

    def search_user(self, username: str) -> Optional[LDAPUser]:
        """Search for user."""
        if self.client:
            return self.client.search_user(username)
        return None

    def search_users(self, filter: str = "", limit: int = 100) -> List[LDAPUser]:
        """Search for users."""
        if self.client:
            return self.client.search_users(filter, limit)
        return []

    def get_user_groups(self, username: str) -> List[str]:
        """Get user's groups."""
        if self.client:
            return self.client.get_user_groups(username)
        return []

    def is_member_of(self, username: str, group: str) -> bool:
        """Check if user is member of group."""
        if self.client:
            return self.client.is_member_of(username, group)
        return False

    def get_status(self) -> Dict[str, Any]:
        """Get integration status."""
        return {
            "enabled": self.config.get("enabled"),
            "server": self.config.get("server"),
            "base_dn": self.config.get("base_dn"),
            "connected": self.client is not None and self.client._connected,
        }
