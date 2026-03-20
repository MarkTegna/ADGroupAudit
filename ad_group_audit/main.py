"""CLI entry point for AD Group Audit.

Modes:
  No args:                  Run full audit (unattended mode)
  --manage:                 Launch GUI for managing audit/protected flags
  --report:                 Generate Excel report of protected groups from DB
  --encode-password <text>: Print ENC: + base64 encoded password and exit
  --version:                Print version info and exit
"""

import argparse
import sys
import traceback

from ad_group_audit.audit_engine import AuditEngine
from ad_group_audit.config_manager import ConfigManager
from ad_group_audit.crypto_utils import encode_password
from ad_group_audit.db_service import DatabaseService
from ad_group_audit.email_service import EmailService
from ad_group_audit.logger import AuditLogger
from ad_group_audit.version import __author__, __compile_date__, __version__

DEFAULT_INI = "ad_group_audit.ini"


def parse_args(args=None):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="ad-group-audit",
        description=(
            f"AD Group Audit v{__version__} - "
            "Active Directory group membership auditing tool.\n"
            f"Author: {__author__} | Compiled: {__compile_date__}"
        ),
    )
    parser.add_argument(
        "--version", action="store_true",
        help="Print version info and exit",
    )
    parser.add_argument(
        "--encode-password", metavar="PLAINTEXT",
        help="Encode a plain-text password for use in the INI file",
    )
    parser.add_argument(
        "--config", default=DEFAULT_INI,
        help=f"Path to INI config file (default: {DEFAULT_INI})",
    )
    parser.add_argument(
        "--manage", action="store_true",
        help="Launch GUI for managing group audit/protected flags and monitored OUs",
    )
    parser.add_argument(
        "--report", nargs="?", const="", default=None, metavar="FILENAME",
        help="Generate Excel report of protected groups (optional: specify output filename)",
    )
    return parser.parse_args(args)


def main(args=None) -> int:
    """Entry point. Returns exit code (0=success, non-zero=error)."""
    parsed = parse_args(args)

    # --version mode
    if parsed.version:
        print(f"AD Group Audit v{__version__}")
        print(f"Author: {__author__}")
        print(f"Compile Date: {__compile_date__}")
        return 0

    # --encode-password mode
    if parsed.encode_password is not None:
        encoded = encode_password(parsed.encode_password)
        print(encoded)
        return 0

    # --manage mode (GUI)
    if parsed.manage:
        try:
            from ad_group_audit.gui import AuditManagerGUI

            config_mgr = ConfigManager(parsed.config)
            config = config_mgr.load()

            db = DatabaseService(config.database)
            db.connect()
            db.ensure_schema()

            gui = AuditManagerGUI(config, db)
            gui.run()

            db.disconnect()
            return 0
        except Exception as e:
            print(f"Error launching GUI: {e}", file=sys.stderr)
            traceback.print_exc()
            return 1

    # --report mode
    if parsed.report is not None:
        try:
            from ad_group_audit.report import generate_report

            config_mgr = ConfigManager(parsed.config)
            config = config_mgr.load()

            db = DatabaseService(config.database)
            db.connect()

            output = parsed.report if parsed.report else None
            generate_report(db, output_path=output)

            db.disconnect()
            return 0
        except Exception as e:
            print(f"Error generating report: {e}", file=sys.stderr)
            traceback.print_exc()
            return 1

    # Full audit mode
    try:
        # Setup logging (interactive if running from console)
        audit_logger = AuditLogger()
        interactive = sys.stdout.isatty()
        logger = audit_logger.setup(interactive=interactive)

        logger.info("AD Group Audit v%s starting", __version__)

        # Load config
        config_mgr = ConfigManager(parsed.config)
        config = config_mgr.load()

        # Connect to database
        db = DatabaseService(config.database)
        db.connect()
        db.ensure_schema()

        # Setup email service
        email = EmailService(config.email)

        # Run audit
        engine = AuditEngine(config, db, email)
        exit_code = engine.run()

        db.disconnect()
        logger.info("AD Group Audit completed with exit code %d", exit_code)
        return exit_code

    except Exception as e:
        try:
            logger.error("Unrecoverable error: %s\n%s", e,
                         traceback.format_exc())
        except NameError:
            print(f"Unrecoverable error: {e}", file=sys.stderr)
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
