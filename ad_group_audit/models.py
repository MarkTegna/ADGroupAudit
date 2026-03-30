"""Data model classes for AD Group Audit."""

from dataclasses import dataclass, field
from datetime import date
from typing import Optional


@dataclass
class DatabaseConfig:
    enabled: bool
    server: str
    port: int
    database: str
    username: str
    password: str
    trust_server_certificate: bool
    connection_timeout: int
    command_timeout: int


@dataclass
class EmailConfig:
    send_email: bool
    smtp_server: str
    smtp_port: int
    smtp_use_tls: bool
    smtp_username: str
    smtp_password: str
    from_email: str
    to_email: str


@dataclass
class DomainConfig:
    name: str
    ldap_server: str
    base_dn: str
    ldap_username: str = ""
    ldap_password: str = ""


@dataclass
class AppConfig:
    database: DatabaseConfig
    email: EmailConfig
    domains: list


@dataclass
class ADGroup:
    dn: str
    name: str
    usn_changed: int
    domain: str


@dataclass
class AuditedGroup:
    dn: str
    name: str
    domain: str
    is_audited: bool
    is_protected: bool
    stored_usn: Optional[int] = None


@dataclass
class MemberRecord:
    member_dn: str
    member_guid: str
    group_dn: str
    first_seen: date
    first_not_seen: Optional[date] = None


@dataclass
class MembershipDiff:
    group_dn: str
    group_name: str
    domain: str
    added: list = field(default_factory=list)
    removed: list = field(default_factory=list)


@dataclass
class MembershipChangeAlert:
    group_name: str
    domain: str
    added: list = field(default_factory=list)
    removed: list = field(default_factory=list)
