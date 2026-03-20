"""Email service for AD Group Audit.

Sends SMTP email alerts for protected group membership changes.
"""

import logging
import smtplib
from email.mime.text import MIMEText

from ad_group_audit.models import EmailConfig, MembershipChangeAlert

logger = logging.getLogger("ad_group_audit")


class EmailService:
    """Sends email alerts for membership changes in protected groups."""

    def __init__(self, email_config: EmailConfig):
        self.config = email_config

    def send_alert(self, alert: MembershipChangeAlert) -> bool:
        """Send an email alert for membership changes.

        Args:
            alert: MembershipChangeAlert with group info and changes.

        Returns:
            True if email sent successfully, False otherwise.
        """
        if not self.config.send_email:
            logger.info("Email alerting disabled, skipping alert for %s",
                        alert.group_name)
            return False

        body = self._build_body(alert)
        msg = MIMEText(body, "plain")
        msg["Subject"] = (
            f"AD Group Audit Alert: Membership change in {alert.group_name}"
        )
        msg["From"] = self.config.from_email
        msg["To"] = self.config.to_email

        try:
            with smtplib.SMTP(self.config.smtp_server,
                              self.config.smtp_port) as smtp:
                if self.config.smtp_use_tls:
                    smtp.starttls()
                if self.config.smtp_username:
                    smtp.login(self.config.smtp_username,
                               self.config.smtp_password)
                smtp.sendmail(self.config.from_email,
                              self.config.to_email.split(","),
                              msg.as_string())
            logger.info("Email alert sent for group: %s", alert.group_name)
            return True
        except smtplib.SMTPException as e:
            logger.error("Failed to send email alert for %s: %s",
                         alert.group_name, e)
            return False

    @staticmethod
    def _build_body(alert: MembershipChangeAlert) -> str:
        """Build the email body text."""
        lines = [
            "AD Group Audit - Membership Change Alert",
            "",
            f"Group: {alert.group_name}",
            f"Domain: {alert.domain}",
            "",
        ]
        if alert.added:
            lines.append("Members Added:")
            for member in alert.added:
                lines.append(f"  + {member}")
            lines.append("")
        if alert.removed:
            lines.append("Members Removed:")
            for member in alert.removed:
                lines.append(f"  - {member}")
            lines.append("")
        return "\n".join(lines)
