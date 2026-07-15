"""
Secret validation module.
Ensures all required secrets are properly configured at startup.
"""

import os
import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws_secret_access_key[\s]*=[\s]*[\"\']([A-Za-z0-9/+=]{40})[\"\']",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "generic_secret": r"(?i)(?:secret|password|api_key|token)[\s]*=[\s]*[\"\']([^\"\']{16,})[\"\']",
    "jwt_secret": r"(?i)jwt.*secret.*=.*[\"\']([^\"\']{32,})[\"\']",
    "database_url": r"(?:postgres|mysql|mongodb)://[^:]+:[^@]+@",
}


class SecretValidator:
    """Validates secret configuration and detects hardcoded secrets."""

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.required_secrets = [
            "SECRET_KEY",
            "POSTGRES_PASSWORD",
            "NEO4J_PASSWORD",
            "DATABASE_URL",
        ]
        self.optional_secrets = [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "SENTRY_DSN",
            "SLACK_WEBHOOK_URL",
        ]

    def validate_required_secrets(self) -> bool:
        """Check that all required secrets are set in environment."""
        all_valid = True

        for secret in self.required_secrets:
            value = os.getenv(secret)

            if not value:
                self.errors.append(f"Required secret {secret} is not set")
                all_valid = False
            elif len(value) < 16 and secret != "DATABASE_URL":
                self.warnings.append(
                    f"Secret {secret} is shorter than recommended (16 chars)"
                )

            if secret == "SECRET_KEY" and value:
                if len(value) < 32:
                    self.errors.append("SECRET_KEY must be at least 32 characters")
                    all_valid = False

                weak_keys = ["secret", "password", "123456", "admin", "changeme"]
                if any(weak in value.lower() for weak in weak_keys):
                    self.errors.append("SECRET_KEY contains common weak patterns")
                    all_valid = False

        return all_valid

    def check_for_hardcoded_secrets(
        self, file_paths: List[str]
    ) -> Dict[str, List[str]]:
        """Scan source files for hardcoded secrets."""
        findings = {}

        for file_path in file_paths:
            try:
                with open(file_path, "r") as f:
                    content = f.read()

                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        if file_path not in findings:
                            findings[file_path] = []
                        findings[file_path].append(
                            f"Potential {secret_type} found (line content truncated)"
                        )
            except Exception:
                pass

        return findings

    def validate_placeholder_values(self) -> bool:
        """Check for placeholder or default values that should be changed."""
        placeholders = [
            ("password", "password", "Default password not changed"),
            ("secret", "secret", "Default secret not changed"),
            ("changeme", "changeme", "Default password not changed"),
            ("admin", "admin", "Default admin credentials not changed"),
        ]

        all_valid = True
        for secret in self.required_secrets:
            value = os.getenv(secret, "")
            for placeholder, _, message in placeholders:
                if placeholder in value.lower():
                    self.warnings.append(f"{secret}: {message}")

        return all_valid

    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """Run all validations."""
        self.validate_required_secrets()
        self.validate_placeholder_values()

        is_valid = len(self.errors) == 0

        return is_valid, self.errors, self.warnings


def validate_secrets_on_startup():
    """Run secret validation at application startup."""
    validator = SecretValidator()
    is_valid, errors, warnings = validator.validate_all()

    for warning in warnings:
        logger.warning(f"Secret validation warning: {warning}")

    for error in errors:
        logger.error(f"Secret validation error: {error}")

    if not is_valid:
        logger.error("Secret validation failed. Check configuration before continuing.")

        if os.getenv("APP_ENV") == "production":
            logger.critical("Running in production without valid secrets. Exiting.")
            import sys

            sys.exit(1)

    logger.info("Secret validation completed")
    return is_valid


def scan_file_for_secrets(file_path: str) -> List[str]:
    """Scan a single file for potential secrets."""
    validator = SecretValidator()
    findings = validator.check_for_hardcoded_secrets([file_path])
    return findings.get(file_path, [])


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("Guardrail AI - Secret Validation")
    print("=" * 60)

    is_valid, errors, warnings = SecretValidator().validate_all()

    print(f"\n{'✓' if is_valid else '✗'} Configuration valid: {is_valid}")

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    print("\nAll secrets validated successfully.")
