"""
HashiCorp Vault Integration Service.
Provides integration with HashiCorp Vault for secrets management.
"""

import logging
import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

import hvac

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class VaultSecret:
    """Vault secret data."""

    path: str = ""
    data: Dict[str, Any] = None
    version: int = 0
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}
        if self.metadata is None:
            self.metadata = {}


class VaultConfig:
    """HashiCorp Vault configuration manager."""

    @staticmethod
    def get_config() -> Dict[str, Any]:
        """Get Vault configuration."""
        return {
            "enabled": getattr(settings, "VAULT_ENABLED", False),
            "url": getattr(settings, "VAULT_ADDR", "http://localhost:8200"),
            "token": getattr(settings, "VAULT_TOKEN", ""),
            "mount_point": getattr(settings, "VAULT_MOUNT_POINT", "secret"),
            "kv_version": getattr(settings, "VAULT_KV_VERSION", 2),
            "namespace": getattr(settings, "VAULT_NAMESPACE", ""),
            "cert_path": getattr(settings, "VAULT_CERT_PATH", ""),
            "key_path": getattr(settings, "VAULT_KEY_PATH", ""),
            "ca_path": getattr(settings, "VAULT_CA_PATH", ""),
            "timeout": getattr(settings, "VAULT_TIMEOUT", 10),
        }


class VaultClient:
    """HashiCorp Vault client."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client: Optional[hvac.Client] = None
        self._connected = False

        if config.get("enabled"):
            self._connect()

    def _connect(self):
        """Connect to Vault server."""
        try:
            url = self.config.get("url", "http://localhost:8200")
            token = self.config.get("token", os.environ.get("VAULT_TOKEN"))

            if not token:
                token = os.environ.get("VAULT_TOKEN", "")
                if not token:
                    logger.warning("No Vault token provided")
                    return

            client_kwargs = {
                "url": url,
                "token": token,
                "timeout": self.config.get("timeout", 10),
            }

            if self.config.get("namespace"):
                client_kwargs["namespace"] = self.config.get("namespace")

            if self.config.get("cert_path") and self.config.get("key_path"):
                client_kwargs["cert"] = (
                    self.config.get("cert_path"),
                    self.config.get("key_path"),
                )

            if self.config.get("ca_path"):
                client_kwargs["verify"] = self.config.get("ca_path")

            self.client = hvac.Client(**client_kwargs)

            if self.client.is_authenticated():
                self._connected = True
                logger.info(f"Connected to Vault: {url}")
            else:
                logger.warning("Vault authentication failed")
        except Exception as e:
            logger.error(f"Vault connection error: {e}")
            self._connected = False

    def read_secret(self, path: str) -> Optional[VaultSecret]:
        """Read a secret from Vault."""
        if not self._connected or not self.client:
            return None

        try:
            mount_point = self.config.get("mount_point", "secret")
            kv_version = self.config.get("kv_version", 2)

            if kv_version == 2:
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=mount_point
                )
            else:
                response = self.client.secrets.kv.v1.read_secret(
                    path=path, mount_point=mount_point
                )

            if response:
                return VaultSecret(
                    path=path,
                    data=response.get("data", {}),
                    version=response.get("version", 0),
                    metadata=response.get("metadata", {}),
                )
        except hvac.exceptions.VaultNotFound:
            logger.warning(f"Vault secret not found: {path}")
        except Exception as e:
            logger.error(f"Vault read error: {e}")

        return None

    def write_secret(self, path: str, data: Dict[str, Any]) -> bool:
        """Write a secret to Vault."""
        if not self._connected or not self.client:
            return False

        try:
            mount_point = self.config.get("mount_point", "secret")
            kv_version = self.config.get("kv_version", 2)

            if kv_version == 2:
                self.client.secrets.kv.v2.write_secret_version(
                    path=path, secret=data, mount_point=mount_point
                )
            else:
                self.client.secrets.kv.v1.write_secret(
                    path=path, secret=data, mount_point=mount_point
                )

            logger.info(f"Secret written to Vault: {path}")
            return True
        except Exception as e:
            logger.error(f"Vault write error: {e}")
            return False

    def delete_secret(self, path: str) -> bool:
        """Delete a secret from Vault."""
        if not self._connected or not self.client:
            return False

        try:
            mount_point = self.config.get("mount_point", "secret")
            kv_version = self.config.get("kv_version", 2)

            if kv_version == 2:
                self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path, mount_point=mount_point
                )
            else:
                self.client.secrets.kv.v1.delete_secret(
                    path=path, mount_point=mount_point
                )

            logger.info(f"Secret deleted from Vault: {path}")
            return True
        except Exception as e:
            logger.error(f"Vault delete error: {e}")
            return False

    def list_secrets(self, path: str) -> List[str]:
        """List secrets at path."""
        if not self._connected or not self.client:
            return []

        try:
            mount_point = self.config.get("mount_point", "secret")
            kv_version = self.config.get("kv_version", 2)

            if kv_version == 2:
                response = self.client.secrets.kv.v2.list_secrets(
                    path=path, mount_point=mount_point
                )
            else:
                response = self.client.secrets.kv.v1.list_secrets(
                    path=path, mount_point=mount_point
                )

            return response.get("data", {}).get("keys", [])
        except Exception as e:
            logger.error(f"Vault list error: {e}")
            return []

    def get_secret_value(self, path: str, key: str) -> Optional[str]:
        """Get a specific key from a secret."""
        secret = self.read_secret(path)
        if secret and key in secret.data:
            return secret.data[key]
        return None

    def get_database_credentials(self, role: str) -> Optional[Dict[str, str]]:
        """Get database credentials from Vault."""
        if not self._connected or not self.client:
            return None

        try:
            response = self.client.secrets.database.get_credentials(role=role)
            return {
                "username": response["username"],
                "password": response["password"],
            }
        except Exception as e:
            logger.error(f"Vault database credentials error: {e}")
            return None

    def get_aws_credentials(self, role: str) -> Optional[Dict[str, str]]:
        """Get AWS credentials from Vault."""
        if not self._connected or not self.client:
            return None

        try:
            response = self.client.secrets.aws.get_credentials(role=role)
            return {
                "access_key": response["access_key"],
                "secret_key": response["secret_key"],
                "security_token": response.get("security_token"),
            }
        except Exception as e:
            logger.error(f"Vault AWS credentials error: {e}")
            return None


class VaultService:
    """Main Vault integration service."""

    def __init__(self):
        self.config = VaultConfig.get_config()
        self.client: Optional[VaultClient] = None

        if self.config.get("enabled"):
            if self.config.get("url") and self.config.get("token"):
                self.client = VaultClient(self.config)
            else:
                logger.warning("Vault enabled but missing URL or token")

    def read_secret(self, path: str) -> Optional[VaultSecret]:
        """Read a secret."""
        if self.client:
            return self.client.read_secret(path)
        return None

    def write_secret(self, path: str, data: Dict[str, Any]) -> bool:
        """Write a secret."""
        if self.client:
            return self.client.write_secret(path, data)
        return False

    def delete_secret(self, path: str) -> bool:
        """Delete a secret."""
        if self.client:
            return self.client.delete_secret(path)
        return False

    def list_secrets(self, path: str) -> List[str]:
        """List secrets."""
        if self.client:
            return self.client.list_secrets(path)
        return []

    def get_secret_value(self, path: str, key: str) -> Optional[str]:
        """Get a specific key from a secret."""
        if self.client:
            return self.client.get_secret_value(path, key)
        return None

    def get_database_credentials(self, role: str) -> Optional[Dict[str, str]]:
        """Get database credentials."""
        if self.client:
            return self.client.get_database_credentials(role)
        return None

    def get_aws_credentials(self, role: str) -> Optional[Dict[str, str]]:
        """Get AWS credentials."""
        if self.client:
            return self.client.get_aws_credentials(role)
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get integration status."""
        return {
            "enabled": self.config.get("enabled"),
            "url": self.config.get("url"),
            "mount_point": self.config.get("mount_point"),
            "kv_version": self.config.get("kv_version"),
            "connected": self.client is not None and self.client._connected,
        }
