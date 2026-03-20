"""Configuration manager for AD Group Audit.

Reads and validates INI configuration. Creates default INI if missing.
Auto-encodes plain-text passwords with ENC: prefix on load.
"""

import configparser
import logging
import os
import sys

from ad_group_audit.crypto_utils import decode_password, encode_password, is_encoded
from ad_group_audit.models import (
    AppConfig,
    DatabaseConfig,
    DomainConfig,
    EmailConfig,
)

logger = logging.getLogger("ad_group_audit")


class ConfigManager:
    """Manages INI file configuration."""

    def __init__(self, ini_path: str):
        self.ini_path = ini_path
        self._parser = configparser.ConfigParser()

    def load(self) -> AppConfig:
        """Load configuration from INI file.

        Auto-encodes plain-text passwords, then parses all sections.
        Returns AppConfig with decoded passwords for runtime use.
        """
        if not os.path.exists(self.ini_path):
            logger.info("INI file not found, creating default: %s", self.ini_path)
            self.create_default()

        self._parser.read(self.ini_path)
        self._auto_encode_passwords()

        return AppConfig(
            database=self.get_database_config(),
            email=self.get_email_config(),
            domains=self.get_domains(),
        )

    def create_default(self) -> None:
        """Write a default INI file with all sections and default values."""
        content = """; AD Group Audit Configuration
; Generated automatically - edit as needed

[database]
enabled = true
server = eit-prisqldb01.tgna.tegna.com
port = 1433
database = ADGroupAudit
username = NetWalker
password = ENC:Rmx1ZmZ5QnVubnlIaXRieWFCdXM=
trust_server_certificate = true
connection_timeout = 30
command_timeout = 60

[email]
send_email = true
smtp_server = relay.tgna.tegna.com
smtp_port = 25
smtp_use_tls = false
smtp_username =
smtp_password =
from_email = ntp-monitor@tgna.tegna.com
to_email = moldham@tegna.com
; subject_prefix = [AD Group Audit]

[domain]
domains = tgna.tegna.com
; domains = tgna.tegna.com, other.domain.com
; ldap_username = DOMAIN\\username
; ldap_password =
"""
        with open(self.ini_path, "w", encoding="utf-8") as f:
            f.write(content)
        # Re-read after creating
        self._parser.read(self.ini_path)

    def _auto_encode_passwords(self) -> bool:
        """Scan password fields and encode plain-text values with ENC: prefix.

        Writes encoded values back to the INI file on disk.
        Returns True if any field was updated.
        """
        updated = False
        password_fields = [
            ("database", "password"),
            ("email", "smtp_password"),
            ("domain", "ldap_password"),
        ]
        for section, key in password_fields:
            if self._parser.has_option(section, key):
                value = self._parser.get(section, key).strip()
                if value and not is_encoded(value):
                    encoded = encode_password(value)
                    self._parser.set(section, key, encoded)
                    updated = True

        if updated:
            with open(self.ini_path, "w", encoding="utf-8") as f:
                self._parser.write(f)
            # Re-read to keep parser in sync
            self._parser.read(self.ini_path)

        return updated

    def _require(self, section: str, key: str) -> str:
        """Get a required config value or log error and exit."""
        if not self._parser.has_section(section):
            logger.error("Missing required config section: [%s]", section)
            sys.exit(1)
        if not self._parser.has_option(section, key):
            logger.error("Missing required config key: [%s] %s", section, key)
            sys.exit(1)
        return self._parser.get(section, key).strip()

    def get_database_config(self) -> DatabaseConfig:
        """Parse [database] section into DatabaseConfig."""
        return DatabaseConfig(
            enabled=self._require("database", "enabled").lower() == "true",
            server=self._require("database", "server"),
            port=int(self._require("database", "port")),
            database=self._require("database", "database"),
            username=self._require("database", "username"),
            password=decode_password(self._require("database", "password")),
            trust_server_certificate=self._require("database", "trust_server_certificate").lower() == "true",
            connection_timeout=int(self._require("database", "connection_timeout")),
            command_timeout=int(self._require("database", "command_timeout")),
        )

    def get_email_config(self) -> EmailConfig:
        """Parse [email] section into EmailConfig."""
        return EmailConfig(
            send_email=self._require("email", "send_email").lower() == "true",
            smtp_server=self._require("email", "smtp_server"),
            smtp_port=int(self._require("email", "smtp_port")),
            smtp_use_tls=self._require("email", "smtp_use_tls").lower() == "true",
            smtp_username=self._require("email", "smtp_username"),
            smtp_password=decode_password(self._require("email", "smtp_password")),
            from_email=self._require("email", "from_email"),
            to_email=self._require("email", "to_email"),
        )

    def get_domains(self) -> list:
        """Parse [domain] section into list of DomainConfig objects."""
        domains_str = self._require("domain", "domains")
        domain_names = [d.strip() for d in domains_str.split(",") if d.strip()]

        # Optional LDAP credentials
        ldap_username = ""
        ldap_password = ""
        if self._parser.has_option("domain", "ldap_username"):
            ldap_username = self._parser.get("domain", "ldap_username").strip()
        if self._parser.has_option("domain", "ldap_password"):
            raw = self._parser.get("domain", "ldap_password").strip()
            ldap_password = decode_password(raw) if raw else ""

        result = []
        for name in domain_names:
            # Derive base DN from domain name: tgna.tegna.com -> DC=tgna,DC=tegna,DC=com
            parts = name.split(".")
            base_dn = ",".join(f"DC={p}" for p in parts)
            result.append(DomainConfig(
                name=name,
                ldap_server=name,
                base_dn=base_dn,
                ldap_username=ldap_username,
                ldap_password=ldap_password,
            ))
        return result
