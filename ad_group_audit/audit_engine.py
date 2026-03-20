"""Audit engine for AD Group Audit.

Orchestrates the full audit pipeline: poll AD, diff membership, persist changes, send alerts.
"""

import logging
from datetime import date

from ad_group_audit.ad_service import ADService
from ad_group_audit.db_service import DatabaseService
from ad_group_audit.email_service import EmailService
from ad_group_audit.models import (
    AppConfig,
    AuditedGroup,
    DomainConfig,
    MembershipChangeAlert,
    MembershipDiff,
)

logger = logging.getLogger("ad_group_audit")


def diff_membership(current: set, stored: list) -> MembershipDiff:
    """Pure function: compute membership diff between AD and DB.

    Args:
        current: Set of member DNs currently in AD.
        stored: List of MemberRecord objects from DB (active members only).

    Returns:
        MembershipDiff with added and removed lists.
    """
    stored_active = {r.member_dn for r in stored}
    added = list(current - stored_active)
    removed = list(stored_active - current)
    return MembershipDiff(
        group_dn="",
        group_name="",
        domain="",
        added=added,
        removed=removed,
    )


class AuditEngine:
    """Orchestrates the full audit pipeline."""

    def __init__(self, config: AppConfig, db: DatabaseService,
                 email: EmailService):
        self.config = config
        self.db = db
        self.email = email

    def run(self) -> int:
        """Run audit for all configured domains. Returns exit code."""
        logger.info("Audit run started")
        failures = 0
        for domain_config in self.config.domains:
            try:
                self.audit_domain(domain_config)
            except Exception as e:
                logger.error("Failed to audit domain %s: %s",
                             domain_config.name, e)
                failures += 1
        logger.info("Audit run completed")
        return 1 if failures == len(self.config.domains) else 0

    def audit_domain(self, domain_config: DomainConfig) -> None:
        """Audit a single domain: fetch AD data, sync to DB, audit protected groups.

        Fetches all groups and OUs from AD first, then disconnects to avoid
        LDAP timeout during the lengthy DB sync. Reconnects for the audit phase.
        """
        ad = ADService(domain_config,
                      username=domain_config.ldap_username,
                      password=domain_config.ldap_password)
        ad.connect()

        # Phase 1: Fetch all data from AD into memory
        all_groups = ad.get_all_groups()
        logger.info("Discovered %d groups in domain %s",
                    len(all_groups), domain_config.name)

        all_ous = ad.get_all_ous()
        logger.info("Discovered %d OUs in domain %s",
                    len(all_ous), domain_config.name)

        ad.disconnect()

        # Phase 2: Sync to DB (no AD connection needed)
        self.db.upsert_groups_batch(all_groups, domain_config.name)
        self.db.upsert_ous_batch(all_ous, domain_config.name)

        # Phase 3: Reconnect to AD and audit protected groups
        protected_groups = self.db.get_protected_groups(domain_config.name)
        if not protected_groups:
            logger.info("No protected groups to audit in %s",
                        domain_config.name)
            return

        ad.connect()
        try:
            for group in protected_groups:
                try:
                    self.audit_group(group, ad)
                except Exception as e:
                    logger.error("Error auditing group %s: %s", group.dn, e)
        finally:
            ad.disconnect()

    def audit_group(self, group: AuditedGroup, ad: ADService) -> MembershipDiff | None:
        """Audit a single group: check USN, diff membership, update DB, alert."""
        # USN optimization: skip if unchanged
        current_usn = ad.get_group_usn(group.dn)
        if group.stored_usn is not None and current_usn == group.stored_usn:
            logger.info("Group %s unchanged (USN %d), skipping",
                        group.name, current_usn)
            return None

        logger.info("Group %s changed (USN %s -> %d), enumerating members",
                     group.name, group.stored_usn, current_usn)

        # Get current members from AD
        current_members = set(ad.get_group_members(group.dn))

        # Get stored active members from DB
        stored_members = self.db.get_active_members(group.dn)

        # Compute diff
        diff = diff_membership(current_members, stored_members)
        diff.group_dn = group.dn
        diff.group_name = group.name
        diff.domain = group.domain

        today = date.today()

        # Record added members
        for member_dn in diff.added:
            self.db.add_member(group.dn, member_dn, today, group.domain)
            logger.info("  Added: %s -> %s", member_dn, group.name)

        # Record removed members
        for member_dn in diff.removed:
            self.db.mark_member_removed(group.dn, member_dn, today)
            logger.info("  Removed: %s from %s", member_dn, group.name)

        # Update stored USN
        self.db.update_usn(group.dn, current_usn)

        # Send email alert if protected and changes detected
        if group.is_protected and (diff.added or diff.removed):
            alert = MembershipChangeAlert(
                group_name=group.name,
                domain=group.domain,
                added=diff.added,
                removed=diff.removed,
            )
            sent = self.email.send_alert(alert)
            if sent:
                logger.info("Email alert sent for protected group: %s",
                            group.name)
            else:
                logger.warning("Email alert failed for protected group: %s",
                               group.name)

        return diff
