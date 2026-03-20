"""Database service for AD Group Audit.

Manages all SQL Server interactions using pyodbc.
"""

import logging
from datetime import date

import pyodbc

from ad_group_audit.models import (
    ADGroup,
    AuditedGroup,
    DatabaseConfig,
    MemberRecord,
)

logger = logging.getLogger("ad_group_audit")


class DatabaseService:
    """Manages SQL Server database operations."""

    def __init__(self, db_config: DatabaseConfig):
        self.config = db_config
        self.conn = None

    def connect(self) -> None:
        """Connect to SQL Server using config parameters."""
        try:
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={self.config.server},{self.config.port};"
                f"DATABASE={self.config.database};"
                f"UID={self.config.username};"
                f"PWD={self.config.password};"
                f"TrustServerCertificate={'yes' if self.config.trust_server_certificate else 'no'};"
                f"Connection Timeout={self.config.connection_timeout};"
            )
            self.conn = pyodbc.connect(conn_str)
            self.conn.timeout = self.config.command_timeout
            logger.info("Connected to SQL Server: %s:%s/%s",
                        self.config.server, self.config.port, self.config.database)
        except pyodbc.Error as e:
            logger.error("SQL Server connection failed - Server: %s, Port: %s, Database: %s - %s",
                         self.config.server, self.config.port, self.config.database, e)
            raise

    def ensure_schema(self) -> None:
        """Create required tables if they don't exist."""
        cursor = self.conn.cursor()
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Groups')
            CREATE TABLE Groups (
                id INT IDENTITY(1,1) PRIMARY KEY,
                dn NVARCHAR(1000) NOT NULL,
                name NVARCHAR(255) NOT NULL,
                domain NVARCHAR(255) NOT NULL,
                is_audited BIT NOT NULL DEFAULT 0,
                is_protected BIT NOT NULL DEFAULT 0,
                usn_changed BIGINT NULL,
                created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
                updated_at DATETIME2 NOT NULL DEFAULT GETDATE(),
                CONSTRAINT UQ_Groups_dn_domain UNIQUE (dn, domain)
            )
        """)
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Membership')
            CREATE TABLE Membership (
                id INT IDENTITY(1,1) PRIMARY KEY,
                group_dn NVARCHAR(1000) NOT NULL,
                member_dn NVARCHAR(1000) NOT NULL,
                domain NVARCHAR(255) NOT NULL,
                first_seen DATE NOT NULL,
                first_not_seen DATE NULL,
                created_at DATETIME2 NOT NULL DEFAULT GETDATE()
            )
        """)
        # Index for fast membership lookups by group
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.indexes
                          WHERE name = 'IX_Membership_group_dn'
                          AND object_id = OBJECT_ID('Membership'))
            CREATE NONCLUSTERED INDEX IX_Membership_group_dn
            ON Membership (group_dn) INCLUDE (member_dn, first_not_seen)
        """)
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'MonitoredOUs')
            CREATE TABLE MonitoredOUs (
                id INT IDENTITY(1,1) PRIMARY KEY,
                ou_dn NVARCHAR(1000) NOT NULL,
                ou_name NVARCHAR(255) NOT NULL DEFAULT '',
                domain NVARCHAR(255) NOT NULL,
                is_monitored BIT NOT NULL DEFAULT 0,
                is_protected BIT NOT NULL DEFAULT 0,
                created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
                updated_at DATETIME2 NOT NULL DEFAULT GETDATE(),
                CONSTRAINT UQ_MonitoredOUs_dn_domain UNIQUE (ou_dn, domain)
            )
        """)
        # Migrate: add columns if table exists but lacks them
        cursor.execute("""
            IF EXISTS (SELECT * FROM sys.tables WHERE name = 'MonitoredOUs')
               AND NOT EXISTS (SELECT * FROM sys.columns
                               WHERE object_id = OBJECT_ID('MonitoredOUs')
                               AND name = 'is_monitored')
            BEGIN
                ALTER TABLE MonitoredOUs ADD ou_name NVARCHAR(255) NOT NULL DEFAULT '';
                ALTER TABLE MonitoredOUs ADD is_monitored BIT NOT NULL DEFAULT 1;
                ALTER TABLE MonitoredOUs ADD updated_at DATETIME2 NOT NULL DEFAULT GETDATE();
            END
        """)
        cursor.execute("""
            IF EXISTS (SELECT * FROM sys.tables WHERE name = 'MonitoredOUs')
               AND NOT EXISTS (SELECT * FROM sys.columns
                               WHERE object_id = OBJECT_ID('MonitoredOUs')
                               AND name = 'is_protected')
            ALTER TABLE MonitoredOUs ADD is_protected BIT NOT NULL DEFAULT 0
        """)
        # One-time fix: clear USN for protected groups that have no active membership
        # records so the next run forces enumeration.
        cursor.execute("""
            IF EXISTS (SELECT 1 FROM Groups WHERE is_protected = 1 AND usn_changed IS NOT NULL)
            UPDATE Groups SET usn_changed = NULL
            WHERE is_protected = 1 AND usn_changed IS NOT NULL
              AND dn NOT IN (
                  SELECT DISTINCT group_dn FROM Membership WHERE first_not_seen IS NULL
              )
        """)
        self.conn.commit()
        logger.info("Database schema verified/created")

    def disconnect(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.info("Disconnected from SQL Server")

    # --- Group operations ---

    def upsert_group(self, group: ADGroup, domain: str) -> None:
        """Insert a new group or update an existing one.

        For protected groups the USN is NOT overwritten during bulk sync so the
        audit_group flow keeps control of when USN gets updated.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            MERGE Groups AS target
            USING (SELECT ? AS dn, ? AS name, ? AS domain, ? AS usn_changed) AS source
            ON target.dn = source.dn AND target.domain = source.domain
            WHEN MATCHED THEN
                UPDATE SET name = source.name,
                           usn_changed = CASE WHEN target.is_protected = 1
                                              THEN target.usn_changed
                                              ELSE source.usn_changed END,
                           updated_at = GETDATE()
            WHEN NOT MATCHED THEN
                INSERT (dn, name, domain, usn_changed)
                VALUES (source.dn, source.name, source.domain, source.usn_changed);
        """, group.dn, group.name, domain, group.usn_changed)
        self.conn.commit()

    def get_protected_groups(self, domain: str) -> list:
        """Get all protected groups for a domain (these are the groups we audit)."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT dn, name, domain, is_protected, usn_changed
            FROM Groups WHERE domain = ? AND is_protected = 1
        """, domain)
        rows = cursor.fetchall()
        return [
            AuditedGroup(
                dn=row.dn, name=row.name, domain=row.domain,
                is_audited=True, is_protected=bool(row.is_protected),
                stored_usn=row.usn_changed,
            )
            for row in rows
        ]

    def set_group_audited(self, group_dn: str, audited: bool) -> None:
        """Set the audit flag for a group. Clears USN when enabling audit so next run enumerates."""
        cursor = self.conn.cursor()
        if audited:
            cursor.execute(
                "UPDATE Groups SET is_audited = 1, usn_changed = NULL, updated_at = GETDATE() WHERE dn = ?",
                group_dn,
            )
        else:
            cursor.execute(
                "UPDATE Groups SET is_audited = 0, updated_at = GETDATE() WHERE dn = ?",
                group_dn,
            )
        self.conn.commit()

    def ensure_group_audited(self, group_dn: str) -> None:
        """Mark a group as audited if not already. Does NOT clear USN.

        Used by the audit engine for monitored-OU auto-audit so that
        groups already being audited keep their USN and skip re-enumeration.
        Only clears USN for groups that were not previously audited.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE Groups SET is_audited = 1, "
            "usn_changed = CASE WHEN is_audited = 1 THEN usn_changed ELSE NULL END, "
            "updated_at = GETDATE() WHERE dn = ? AND is_audited = 0",
            group_dn,
        )
        self.conn.commit()

    def set_group_protected(self, group_dn: str, protected: bool) -> None:
        """Set the protected flag for a group. Clears USN when enabling so next run enumerates."""
        cursor = self.conn.cursor()
        if protected:
            cursor.execute(
                "UPDATE Groups SET is_protected = 1, usn_changed = NULL, "
                "updated_at = GETDATE() WHERE dn = ?",
                group_dn,
            )
        else:
            cursor.execute(
                "UPDATE Groups SET is_protected = 0, updated_at = GETDATE() WHERE dn = ?",
                group_dn,
            )
        self.conn.commit()

    def get_stored_usn(self, group_dn: str) -> int | None:
        """Get the stored USNChanged value for a group."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT usn_changed FROM Groups WHERE dn = ?", group_dn)
        row = cursor.fetchone()
        return row.usn_changed if row else None

    def update_usn(self, group_dn: str, usn: int) -> None:
        """Update the stored USNChanged value for a group."""
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE Groups SET usn_changed = ?, updated_at = GETDATE() WHERE dn = ?",
            usn, group_dn,
        )
        self.conn.commit()

    # --- OU operations ---

    def upsert_ou(self, ou_dn: str, ou_name: str, domain: str) -> None:
        """Insert a new OU or update its name if it already exists."""
        cursor = self.conn.cursor()
        cursor.execute("""
            MERGE MonitoredOUs AS target
            USING (SELECT ? AS ou_dn, ? AS ou_name, ? AS domain) AS source
            ON target.ou_dn = source.ou_dn AND target.domain = source.domain
            WHEN MATCHED THEN
                UPDATE SET ou_name = source.ou_name, updated_at = GETDATE()
            WHEN NOT MATCHED THEN
                INSERT (ou_dn, ou_name, domain)
                VALUES (source.ou_dn, source.ou_name, source.domain);
        """, ou_dn, ou_name, domain)
        self.conn.commit()

    def set_ou_monitored(self, ou_dn: str, monitored: bool) -> None:
        """Set the monitored flag for an OU."""
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE MonitoredOUs SET is_monitored = ?, updated_at = GETDATE() WHERE ou_dn = ?",
            1 if monitored else 0, ou_dn,
        )
        self.conn.commit()

    def set_ou_protected(self, ou_dn: str, protected: bool) -> None:
        """Set the protected flag for an OU."""
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE MonitoredOUs SET is_protected = ?, updated_at = GETDATE() WHERE ou_dn = ?",
            1 if protected else 0, ou_dn,
        )
        self.conn.commit()

    def add_monitored_ou(self, ou_dn: str, domain: str) -> None:
        """Add an OU to the monitored list (legacy compat)."""
        cursor = self.conn.cursor()
        cursor.execute("""
            IF NOT EXISTS (SELECT 1 FROM MonitoredOUs WHERE ou_dn = ? AND domain = ?)
            INSERT INTO MonitoredOUs (ou_dn, domain, is_monitored) VALUES (?, ?, 1)
        """, ou_dn, domain, ou_dn, domain)
        self.conn.commit()

    def get_monitored_ous(self, domain: str) -> list:
        """Get all monitored OU DNs for a domain."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT ou_dn FROM MonitoredOUs WHERE domain = ? AND is_monitored = 1",
            domain,
        )
        return [row.ou_dn for row in cursor.fetchall()]

    def get_groups_in_ou(self, ou_dn: str, domain: str) -> list:
        """Get DNs of all groups whose DN ends with the given OU DN."""
        cursor = self.conn.cursor()
        pattern = "%," + ou_dn
        cursor.execute(
            "SELECT dn FROM Groups WHERE domain = ? AND dn LIKE ?",
            domain, pattern,
        )
        return [row.dn for row in cursor.fetchall()]

    def get_all_ous(self, domain: str) -> list:
        """Get all OUs for a domain, sorted hierarchically (domain root down)."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT ou_dn, ou_name, domain, is_monitored, is_protected "
            "FROM MonitoredOUs WHERE domain = ?",
            domain,
        )
        rows = [
            {"ou_dn": row.ou_dn, "ou_name": row.ou_name,
             "domain": row.domain, "is_monitored": bool(row.is_monitored),
             "is_protected": bool(row.is_protected)}
            for row in cursor.fetchall()
        ]
        # Sort by reversed DN components so tree reads top-down
        rows.sort(key=lambda r: list(reversed(
            [c.strip() for c in r["ou_dn"].split(",")]
        )))
        return rows


    def get_all_groups_for_domain(self, domain: str) -> list:
        """Get all groups for a domain with audit/protected flags."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT dn, name, is_audited, is_protected "
            "FROM Groups WHERE domain = ?",
            domain,
        )
        return [
            {"dn": row.dn, "name": row.name,
             "is_audited": bool(row.is_audited),
             "is_protected": bool(row.is_protected)}
            for row in cursor.fetchall()
        ]

    def remove_monitored_ou(self, ou_dn: str) -> None:
        """Remove an OU from the monitored list."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM MonitoredOUs WHERE ou_dn = ?", ou_dn)
        self.conn.commit()

    # --- Membership operations ---

    def get_active_members(self, group_dn: str) -> list:
        """Get all active members (first_not_seen IS NULL) for a group."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT member_dn, group_dn, first_seen, first_not_seen
            FROM Membership
            WHERE group_dn = ? AND first_not_seen IS NULL
        """, group_dn)
        return [
            MemberRecord(
                member_dn=row.member_dn, group_dn=row.group_dn,
                first_seen=row.first_seen, first_not_seen=row.first_not_seen,
            )
            for row in cursor.fetchall()
        ]

    def add_member(self, group_dn: str, member_dn: str, first_seen: date,
                   domain: str = "") -> None:
        """Add a new membership record."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO Membership (group_dn, member_dn, domain, first_seen)
            VALUES (?, ?, ?, ?)
        """, group_dn, member_dn, domain, first_seen)
        self.conn.commit()

    def mark_member_removed(self, group_dn: str, member_dn: str,
                            not_seen: date) -> None:
        """Mark an active member as removed by setting first_not_seen date."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE Membership SET first_not_seen = ?
            WHERE group_dn = ? AND member_dn = ? AND first_not_seen IS NULL
        """, not_seen, group_dn, member_dn)
        self.conn.commit()
