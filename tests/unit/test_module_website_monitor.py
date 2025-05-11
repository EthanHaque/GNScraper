"""Unit tests for the email notification functionalities of the WebsiteMonitor class."""

import smtplib
import socket
from unittest.mock import ANY, MagicMock

import pytest

from scraper import website_monitor


@pytest.fixture
def monitor_instance(mocker) -> website_monitor.WebsiteMonitor:
    """Provides a WebsiteMonitor instance with its session creation mocked."""
    mocker.patch("scraper.website_monitor.WebsiteMonitor._create_session_with_retries")
    return website_monitor.WebsiteMonitor()


@pytest.mark.parametrize(
    ("smtp_port", " use_tls", "expect_smtp_ssl"),
    [
        (587, True, False),  # Standard TLS port
        (25, True, False),  # Another port, TLS explicitly enabled
        (465, False, True),  # Standard SSL port, TLS explicitly false
        (465, True, False),  # Port 465 but TLS explicitly true (should use SMTP then starttls)
    ],
)
def test_send_email_notification_success(
    mocker, monitor_instance: website_monitor.WebsiteMonitor, smtp_port: int, use_tls: bool, expect_smtp_ssl: bool
):
    """
    Tests successful email sending via SMTP or SMTP_SSL.
    """
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_smtp_class = mocker.patch("scraper.website_monitor.smtplib.SMTP")
    mock_smtp_ssl_class = mocker.patch("scraper.website_monitor.smtplib.SMTP_SSL")

    mock_smtp_instance = MagicMock()
    if expect_smtp_ssl:
        mock_smtp_ssl_class.return_value.__enter__.return_value = mock_smtp_instance
    else:
        mock_smtp_class.return_value.__enter__.return_value = mock_smtp_instance

    mocker.patch("scraper.website_monitor.SMTP_HOST", "smtp.example.com")
    mocker.patch("scraper.website_monitor.SMTP_PORT", smtp_port)
    mocker.patch("scraper.website_monitor.SMTP_USE_TLS", use_tls)
    mocker.patch("scraper.website_monitor.SMTP_USER", "user@example.com")
    mocker.patch("scraper.website_monitor.SMTP_PASSWORD", "password123")
    mocker.patch("scraper.website_monitor.EMAIL_SENDER", "sender@example.com")

    recipients = ["recipient1@example.com", "recipient2@example.com"]
    subject = "Test Email Subject"
    body = "This is a test email body."

    monitor_instance._send_email_notification(subject, body, recipients)

    if expect_smtp_ssl:
        mock_smtp_ssl_class.assert_called_once_with("smtp.example.com", smtp_port, timeout=10)
        mock_smtp_class.assert_not_called()
        mock_smtp_instance.starttls.assert_not_called()
    else:
        mock_smtp_class.assert_called_once_with("smtp.example.com", smtp_port, timeout=10)
        mock_smtp_ssl_class.assert_not_called()
        if use_tls:
            mock_smtp_instance.starttls.assert_called_once()
        else:
            mock_smtp_instance.starttls.assert_not_called()

    mock_smtp_instance.login.assert_called_once_with("user@example.com", "password123")
    mock_smtp_instance.sendmail.assert_called_once_with("sender@example.com", recipients, ANY)
    sent_message_str = mock_smtp_instance.sendmail.call_args[0][2]
    assert f"Subject: {subject}" in sent_message_str
    assert "From: sender@example.com" in sent_message_str
    assert f"To: {', '.join(recipients)}" in sent_message_str
    assert body in sent_message_str

    mock_logger.info.assert_any_call("Email notification sent successfully.", to=recipients)


def test_send_email_notification_misconfigured(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests that email is not sent if configuration is incomplete."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_smtp_class = mocker.patch("scraper.website_monitor.smtplib.SMTP")

    mocker.patch("scraper.website_monitor.SMTP_HOST", None)
    mocker.patch("scraper.website_monitor.SMTP_USER", "user@example.com")
    mocker.patch("scraper.website_monitor.SMTP_PASSWORD", "password123")
    mocker.patch("scraper.website_monitor.EMAIL_SENDER", "sender@example.com")

    monitor_instance._send_email_notification("Subject", "Body", ["test@example.com"])

    mock_smtp_class.assert_not_called()
    mock_logger.warning.assert_called_with("Email notification misconfigured. Skipping email.", details=ANY)


@pytest.mark.parametrize(
    ("exception_instance", "error_message_part"),
    [
        (smtplib.SMTPAuthenticationError(535, b"Authentication credentials invalid"), "SMTP authentication failed"),
        (smtplib.SMTPServerDisconnected("Server disconnected unexpectedly"), "SMTP server disconnected unexpectedly."),
        (
            smtplib.SMTPException("A generic SMTP error occurred"),
            "Failed to send email notification due to SMTP error.",
        ),
        (socket.gaierror(8, "Name or service not known"), "An unexpected error occurred while sending email"),
        (Exception("An unexpected general error occurred"), "An unexpected error occurred while sending email"),
    ],
)
def test_send_email_notification_smtp_exceptions(
    mocker, monitor_instance: website_monitor.WebsiteMonitor, exception_instance: Exception, error_message_part: str
):
    """Tests logging of various SMTP exceptions during email sending."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_smtp_class = mocker.patch("scraper.website_monitor.smtplib.SMTP")
    mock_smtp_instance = MagicMock()
    mock_smtp_class.return_value.__enter__.return_value = mock_smtp_instance

    mock_smtp_instance.sendmail.side_effect = exception_instance

    mocker.patch("scraper.website_monitor.SMTP_HOST", "smtp.example.com")
    mocker.patch("scraper.website_monitor.SMTP_PORT", 587)
    mocker.patch("scraper.website_monitor.SMTP_USE_TLS", True)
    mocker.patch("scraper.website_monitor.SMTP_USER", "user@example.com")
    mocker.patch("scraper.website_monitor.SMTP_PASSWORD", "password123")
    mocker.patch("scraper.website_monitor.EMAIL_SENDER", "sender@example.com")

    monitor_instance._send_email_notification("Subject", "Body", ["test@example.com"])

    error_logged = False
    logged_errors = []
    if mock_logger.error.call_args_list:
        for call_arg in mock_logger.error.call_args_list:
            logged_errors.append(call_arg.args[0] if call_arg.args else str(call_arg.kwargs))
            if call_arg.args and error_message_part in call_arg.args[0]:
                error_logged = True
                break
    assert error_logged, (
        f"Expected error log containing '{error_message_part}' was not found. Logged errors: {logged_errors}"
    )


def test_notify_content_change_email_enabled_and_configured(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """
    Tests that _notify_content_change calls email method when enabled and configured.
    """
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_send_email = mocker.patch.object(monitor_instance, "_send_email_notification")

    mocker.patch("scraper.website_monitor.EMAIL_NOTIFICATIONS_ENABLED", True)
    mocker.patch("scraper.website_monitor.EMAIL_RECIPIENTS", ["test@example.com"])
    mocker.patch("scraper.website_monitor.SMTP_HOST", "smtp.example.com")
    mocker.patch("scraper.website_monitor.SMTP_USER", "user")
    mocker.patch("scraper.website_monitor.SMTP_PASSWORD", "pass")
    mocker.patch("scraper.website_monitor.EMAIL_SENDER", "sender")

    monitor_instance._notify_content_change("new_hash_val", "old_hash_val")

    mock_logger.info.assert_any_call(
        "CHANGE DETECTED: Monitored content has updated.",
        previous_hash="old_hash_val",
        new_hash="new_hash_val",
        page_url=ANY,
        element_id=ANY,
    )
    mock_send_email.assert_called_once()
    assert "Change Detected" in mock_send_email.call_args[0][0]
    assert "new_hash_val" in mock_send_email.call_args[0][1]
    assert "old_hash_val" in mock_send_email.call_args[0][1]


def test_notify_content_change_email_disabled(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests that email is not sent if email notifications are disabled."""
    mock_send_email = mocker.patch.object(monitor_instance, "_send_email_notification")

    mocker.patch("scraper.website_monitor.EMAIL_NOTIFICATIONS_ENABLED", False)
    mocker.patch("scraper.website_monitor.EMAIL_RECIPIENTS", ["test@example.com"])

    monitor_instance._notify_content_change("new", "old")

    mock_send_email.assert_not_called()


def test_notify_content_change_email_enabled_no_recipients(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests that email notification is skipped if enabled but no recipients are set."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_send_email = mocker.patch.object(monitor_instance, "_send_email_notification")

    mocker.patch("scraper.website_monitor.EMAIL_NOTIFICATIONS_ENABLED", True)
    mocker.patch("scraper.website_monitor.EMAIL_RECIPIENTS", [])
    mocker.patch("scraper.website_monitor.SMTP_HOST", "smtp.example.com")
    mocker.patch("scraper.website_monitor.SMTP_USER", "user")
    mocker.patch("scraper.website_monitor.SMTP_PASSWORD", "pass")
    mocker.patch("scraper.website_monitor.EMAIL_SENDER", "sender")

    monitor_instance._notify_content_change("new", "old")

    mock_send_email.assert_not_called()
    mock_logger.warning.assert_any_call("Email notifications enabled but no recipients configured.")
