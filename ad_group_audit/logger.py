"""Logging configuration for AD Group Audit.

All output uses ASCII-only characters to avoid cp1252 encoding errors on Windows.
Log filename format: YYYYMMDD-HH-MM.log
"""

import logging
import os
from datetime import datetime


class AuditLogger:
    """Configures file and optional console logging."""

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir

    def setup(self, interactive: bool = False) -> logging.Logger:
        """Set up logging with file handler (always) and console handler (when interactive).

        Args:
            interactive: If True, also log to console.

        Returns:
            Configured logger instance.
        """
        os.makedirs(self.log_dir, exist_ok=True)

        now = datetime.now()
        filename = now.strftime("%Y%m%d-%H-%M") + ".log"
        filepath = os.path.join(self.log_dir, filename)

        logger = logging.getLogger("ad_group_audit")
        logger.setLevel(logging.DEBUG)

        # Clear existing handlers to avoid duplicates
        logger.handlers.clear()

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # File handler - always active
        file_handler = logging.FileHandler(filepath, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Console handler - only when interactive
        if interactive:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        return logger
