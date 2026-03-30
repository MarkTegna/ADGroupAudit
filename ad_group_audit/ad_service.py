"""Active Directory service for AD Group Audit.

Wraps LDAP operations against Active Directory using ldap3.
Uses Windows integrated auth (SASL/Kerberos) by default,
falls back to NTLM if explicit credentials are provided.
Resolves DC hostname automatically for Kerberos SPN compatibility.
"""

import logging
import subprocess

from ldap3 import ALL, KERBEROS, NTLM, SASL, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException

from ad_group_audit.models import ADGroup, DomainConfig

logger = logging.getLogger("ad_group_audit")

PAGE_SIZE = 1000


def _ldap_escape(value: str) -> str:
    """Escape special characters for use in LDAP filter values."""
    replacements = [
        ("\\", "\\5c"),
        ("*", "\\2a"),
        ("(", "\\28"),
        (")", "\\29"),
        ("\x00", "\\00"),
    ]
    for char, escaped in replacements:
        value = value.replace(char, escaped)
    return value


def _resolve_dc(domain: str) -> str:
    """Resolve the domain controller hostname for a domain using nltest.

    Falls back to the domain name if resolution fails.
    """
    try:
        result = subprocess.run(
            ["nltest", f"/dsgetdc:{domain}"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if "DC:" in line and "\\\\" in line:
                dc = line.split("\\\\")[-1].strip()
                if dc:
                    logger.info("Resolved DC for %s: %s", domain, dc)
                    return dc
    except Exception as e:
        logger.warning("Could not resolve DC for %s: %s", domain, e)
    return domain


class ADService:
    """Manages LDAP operations against Active Directory."""

    def __init__(self, domain_config: DomainConfig,
                 username: str = "", password: str = ""):
        self.config = domain_config
        self.username = username
        self.password = password
        self.conn = None

    def connect(self) -> None:
        """Connect to Active Directory via LDAP.

        Uses SASL/Kerberos (Windows integrated auth) if no credentials,
        NTLM if explicit credentials are provided.
        Resolves DC hostname for Kerberos SPN compatibility.
        """
        try:
            if self.username:
                # Explicit credentials - use NTLM, connect to domain name
                server = Server(self.config.ldap_server, get_info=ALL)
                self.conn = Connection(
                    server,
                    user=self.username,
                    password=self.password,
                    authentication=NTLM,
                    auto_bind=True,
                )
                logger.info("Connected to AD: %s (NTLM as %s)",
                            self.config.ldap_server, self.username)
            else:
                # No credentials - use Windows integrated auth (Kerberos)
                # Resolve DC hostname for proper Kerberos SPN
                dc_host = _resolve_dc(self.config.name)
                server = Server(dc_host, get_info=ALL)
                self.conn = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=KERBEROS,
                    auto_bind=True,
                )
                logger.info("Connected to AD: %s via DC %s (Kerberos)",
                            self.config.name, dc_host)
        except LDAPException as e:
            logger.error("LDAP connection failed for domain %s: %s",
                         self.config.name, e)
            raise

    def _paged_search(self, search_base: str, search_filter: str,
                      attributes: list) -> list:
        """Perform a paged LDAP search to handle large result sets."""
        self.conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=PAGE_SIZE,
        )
        results = list(self.conn.entries)

        cookie = self.conn.result.get("controls", {}).get(
            "1.2.840.113556.1.4.319", {}
        ).get("value", {}).get("cookie")

        while cookie:
            self.conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=PAGE_SIZE,
                paged_cookie=cookie,
            )
            results.extend(self.conn.entries)
            cookie = self.conn.result.get("controls", {}).get(
                "1.2.840.113556.1.4.319", {}
            ).get("value", {}).get("cookie")

        return results

    def get_all_groups(self) -> list:
        """Query all group objects from the domain base DN."""
        entries = self._paged_search(
            search_base=self.config.base_dn,
            search_filter="(objectClass=group)",
            attributes=["distinguishedName", "cn", "uSNChanged"],
        )
        groups = []
        for entry in entries:
            try:
                groups.append(ADGroup(
                    dn=str(entry.distinguishedName),
                    name=str(entry.cn),
                    usn_changed=int(str(entry.uSNChanged)),
                    domain=self.config.name,
                ))
            except (ValueError, AttributeError) as e:
                logger.warning("Skipping group entry: %s", e)
        return groups

    def get_groups_in_ou(self, ou_dn: str) -> list:
        """Query groups within a specific OU DN."""
        entries = self._paged_search(
            search_base=ou_dn,
            search_filter="(objectClass=group)",
            attributes=["distinguishedName", "cn", "uSNChanged"],
        )
        groups = []
        for entry in entries:
            try:
                groups.append(ADGroup(
                    dn=str(entry.distinguishedName),
                    name=str(entry.cn),
                    usn_changed=int(str(entry.uSNChanged)),
                    domain=self.config.name,
                ))
            except (ValueError, AttributeError) as e:
                logger.warning("Skipping group entry in OU: %s", e)
        return groups

    def get_group_members(self, group_dn: str) -> list:
        """Return list of dicts with member objectGUID and DN for a group.

        Each dict has keys 'guid' (str) and 'dn' (str).
        Uses the group's member attribute to get DNs, then resolves each
        member's objectGUID via a single paged search.
        """
        self.conn.search(
            search_base=group_dn,
            search_filter="(objectClass=group)",
            search_scope=SUBTREE,
            attributes=["member"],
        )
        if not self.conn.entries:
            return []
        entry = self.conn.entries[0]
        if not hasattr(entry, "member") or not entry.member:
            return []

        member_dns = [str(m) for m in entry.member]
        if not member_dns:
            return []

        # Resolve objectGUID for all members in a single search
        # Build an OR filter for all member DNs using distinguishedName
        results = []
        # Process in chunks to avoid overly long LDAP filters
        chunk_size = 50
        for i in range(0, len(member_dns), chunk_size):
            chunk = member_dns[i:i + chunk_size]
            if len(chunk) == 1:
                search_filter = (
                    f"(distinguishedName={_ldap_escape(chunk[0])})"
                )
            else:
                parts = "".join(
                    f"(distinguishedName={_ldap_escape(dn)})"
                    for dn in chunk
                )
                search_filter = f"(|{parts})"

            entries = self._paged_search(
                search_base=self.config.base_dn,
                search_filter=search_filter,
                attributes=["objectGUID", "distinguishedName"],
            )
            for e in entries:
                try:
                    guid = str(e.objectGUID)
                    dn = str(e.distinguishedName)
                    results.append({"guid": guid, "dn": dn})
                except (ValueError, AttributeError) as err:
                    logger.warning("Skipping member entry: %s", err)

        return results

    def get_group_usn(self, group_dn: str) -> int:
        """Return the USNChanged attribute value for a group."""
        self.conn.search(
            search_base=group_dn,
            search_filter="(objectClass=group)",
            search_scope=SUBTREE,
            attributes=["uSNChanged"],
        )
        if self.conn.entries:
            return int(str(self.conn.entries[0].uSNChanged))
        return 0

    def get_all_ous(self) -> list:
        """Query all organizationalUnit objects from the domain.

        Returns list of dicts with 'dn' and 'name' keys.
        """
        entries = self._paged_search(
            search_base=self.config.base_dn,
            search_filter="(objectClass=organizationalUnit)",
            attributes=["distinguishedName", "ou"],
        )
        ous = []
        for entry in entries:
            try:
                ous.append({
                    "dn": str(entry.distinguishedName),
                    "name": str(entry.ou),
                })
            except (ValueError, AttributeError) as e:
                logger.warning("Skipping OU entry: %s", e)
        return ous

    def disconnect(self) -> None:
        """Close the LDAP connection."""
        if self.conn:
            self.conn.unbind()
            self.conn = None
            logger.info("Disconnected from AD: %s", self.config.name)
