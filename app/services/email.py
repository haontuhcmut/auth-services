import logging
from email.message import EmailMessage
from smtplib import SMTP

logger = logging.getLogger(__name__)


def send_password_reset_email(
    *,
    smtp_host: str,
    smtp_port: int,
    sender: str,
    recipient: str,
    reset_url: str,
) -> None:
    message = EmailMessage()
    message["Subject"] = "Reset your password"
    message["From"] = sender
    message["To"] = recipient

    message.set_content(
        f"""You requested a password reset.

Use this link to reset your password:

{reset_url}

This link expires in 15 minutes.

If you did not request this, ignore this email.
"""
    )

    with SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        smtp.send_message(message)


def send_verification_email(
    *,
    smtp_host: str,
    smtp_port: int,
    sender: str,
    recipient: str,
    verification_url: str,
) -> None:
    message = EmailMessage()
    message["Subject"] = "Verify your email address"
    message["From"] = sender
    message["To"] = recipient

    message.set_content(
        f"""
Hello,

Please verify your email address using the link below:

{verification_url}

This link expires in 30 minutes.

If you did not create this account, you can ignore this email.
"""
    )

    with SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        smtp.send_message(message)
