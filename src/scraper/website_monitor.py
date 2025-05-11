"""
Monitors a specific webpage for changes in the content of a target HTML element.

This script periodically fetches a webpage, extracts content from a designated
HTML element, and compares its hash to a previously stored hash. If a change is
detected, a notification is sent.

Required Environment Variables for Notifications:
-----------------------------------------------
Email Notifications:
  EMAIL_NOTIFICATIONS_ENABLED: "true" or "false" (default: "false")
  SMTP_HOST:                 Hostname of your SMTP server (e.g., "smtp.gmail.com")
  SMTP_PORT:                 Port for the SMTP server (e.g., 587 for TLS, 465 for SSL)
  SMTP_USE_TLS:              "true" or "false" (default: "true" if port is 587)
  SMTP_USER:                 Your SMTP username (often your email address)
  SMTP_PASSWORD:             Your SMTP password or App Password (recommended for services like Gmail)
  EMAIL_SENDER:              The "From" email address for notifications
  EMAIL_RECIPIENTS:          Comma-separated list of recipient email addresses
"""

import datetime
import hashlib
import os
import smtplib
import time
from email.mime.text import MIMEText
from typing import Any

import requests
import schedule
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from scraper import logging_config

load_dotenv()

URL: str = "https://store.gamersnexus.net/?category=Garage+Sale"
TARGET_ELEMENT_ID: str = "productList"
USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/91.0.4472.124 Safari/537.36"
)

PEAK_START_HOUR: int = 6
PEAK_END_HOUR: int = 21

PEAK_INTERVAL_MIN: int = 30
PEAK_INTERVAL_MAX: int = 90
OFFPEAK_INTERVAL_MIN: int = 270
OFFPEAK_INTERVAL_MAX: int = 330

REQUEST_TIMEOUT: int = 15

EMAIL_NOTIFICATIONS_ENABLED: bool = os.getenv("EMAIL_NOTIFICATIONS_ENABLED", "false").lower() == "true"
SMTP_HOST: str | None = os.getenv("SMTP_HOST")
SMTP_PORT_STR: str | None = os.getenv("SMTP_PORT")
SMTP_PORT: int = int(SMTP_PORT_STR) if SMTP_PORT_STR and SMTP_PORT_STR.isdigit() else 587
SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "true" if SMTP_PORT == 587 else "false").lower() == "true"
SMTP_USER: str | None = os.getenv("SMTP_USER")
SMTP_PASSWORD: str | None = os.getenv("SMTP_PASSWORD")
EMAIL_SENDER: str | None = os.getenv("EMAIL_SENDER")
EMAIL_RECIPIENTS_STR: str | None = os.getenv("EMAIL_RECIPIENTS")
EMAIL_RECIPIENTS: list[str] = (
    [email.strip() for email in EMAIL_RECIPIENTS_STR.split(",")] if EMAIL_RECIPIENTS_STR else []
)


logging_config.setup_logging()
logger = logging_config.get_logger(__name__)


class WebsiteMonitor:
    """
    Manages the process of monitoring a website for content changes.

    Encapsulates the state and logic for fetching, parsing, hashing,
    scheduling, and notifying of changes to a specific part of a webpage.

    Attributes
    ----------
    previous_content_hash : Optional[str]
        Hash of the target element's content from the previous check.
    current_job : Optional[Any]
        The currently active `schedule` job instance.
    current_schedule_type : Optional[str]
        Indicates the current active schedule type ('peak' or 'offpeak').
    session : requests.Session
        The requests session with retry capabilities, reused for checks.
    """

    def __init__(self) -> None:
        """Initialize the WebsiteMonitor state."""
        self.previous_content_hash: str | None = None
        self.current_job: Any | None = None
        self.current_schedule_type: str | None = None
        self.session: requests.Session = self._create_session_with_retries()
        logger.debug("WebsiteMonitor instance initialized.")

    @staticmethod
    def _create_session_with_retries() -> requests.Session:
        """
        Create and configure a requests Session with retry capabilities.

        Returns
        -------
        requests.Session
            A configured requests Session object.
        """
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": USER_AGENT})
        logger.debug("Requests session created with retry strategy.")
        return session

    def _fetch_content(self, url: str) -> str | None:
        """
        Fetch HTML content from the specified URL using the instance's session.

        Parameters
        ----------
        url : str
            The URL from which to fetch the content.

        Returns
        -------
        Optional[str]
            The HTML content as a string if the request is successful,
            otherwise None.
        """
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            logger.debug("Successfully fetched content.", page_url=url, status_code=response.status_code)
            return response.text
        except requests.exceptions.RequestException as e:
            logger.error("Failed to fetch URL content.", page_url=url, error_message=str(e), exc_info=False)
            return None

    @staticmethod
    def _extract_target_content(html_content: str | None, element_id: str) -> str | None:
        """
        Extract the string representation of a target HTML element.

        Parameters
        ----------
        html_content : Optional[str]
            The HTML content of the page as a string.
        element_id : str
            The ID of the HTML element to extract.

        Returns
        -------
        Optional[str]
            The string representation of the target element if found,
            otherwise None.
        """
        if not html_content:
            logger.debug("HTML content is None, cannot extract target content.")
            return None
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            target_element = soup.find(id=element_id)
            if target_element:
                logger.debug("Target element found.", target_id=element_id)
                return str(target_element)

            logger.warning(
                "Target element not found in HTML content.",
                target_id=element_id,
                page_url=URL,
            )
            return None
        except Exception as e:
            logger.error(
                "Failed to parse HTML or extract element.", target_id=element_id, error_message=str(e), exc_info=True
            )
            return None

    @staticmethod
    def _calculate_hash(content: str | None) -> str:
        """
        Calculate the SHA256 hash of the given string content.

        Parameters
        ----------
        content : Optional[str]
            The string content to hash.

        Returns
        -------
        str
            The hexadecimal SHA256 hash of the content, or a placeholder string
            if content is None.
        """
        if content is None:
            return "element_not_found_or_empty"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _send_email_notification(self, subject: str, body: str, recipients: list[str]) -> None:
        """
        Send an email notification.

        Parameters
        ----------
        subject : str
            The subject of the email.
        body : str
            The plain text body of the email.
        recipients : list[str]
            A list of recipient email addresses.
        """
        if not all([SMTP_HOST, SMTP_USER, SMTP_PASSWORD, EMAIL_SENDER, recipients]):
            logger.warning(
                "Email notification misconfigured. Skipping email.",
                details="SMTP_HOST, SMTP_USER, SMTP_PASSWORD, EMAIL_SENDER, or EMAIL_RECIPIENTS not set.",
            )
            return

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = ", ".join(recipients)

        try:
            logger.info("Attempting to send email notification...", to=recipients, subject=subject)
            if SMTP_PORT == 465 and not SMTP_USE_TLS:
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                    server.sendmail(EMAIL_SENDER, recipients, msg.as_string())
            else:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                    if SMTP_USE_TLS:
                        server.starttls()
                    server.login(SMTP_USER, SMTP_PASSWORD)
                    server.sendmail(EMAIL_SENDER, recipients, msg.as_string())
            logger.info("Email notification sent successfully.", to=recipients)
        except smtplib.SMTPAuthenticationError as e:
            logger.exception("SMTP authentication failed. Check SMTP_USER/SMTP_PASSWORD.", error=str(e), exc_info=False)
        except smtplib.SMTPServerDisconnected:
            logger.exception("SMTP server disconnected unexpectedly.", exc_info=True)
        except smtplib.SMTPException as e:
            logger.exception("Failed to send email notification due to SMTP error.", error=str(e), exc_info=True)
        except Exception as e:
            logger.exception("An unexpected error occurred while sending email.", error=str(e), exc_info=True)

    def _notify_content_change(self, new_hash: str, old_hash: str | None) -> None:
        """
        Log and send notifications that the monitored content has changed.

        Parameters
        ----------
        new_hash : str
            The new hash of the content.
        old_hash : Optional[str]
            The previous hash of the content.
        """
        log_message = "CHANGE DETECTED: Monitored content has updated."
        details = {
            "previous_hash": old_hash if old_hash else "N/A (was not found or initial)",
            "new_hash": new_hash,
            "page_url": URL,
            "element_id": TARGET_ELEMENT_ID,
        }
        logger.info(log_message, **details)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
        subject = f"Change Detected on {URL}"
        body = (
            f"Alert: Content change detected on page.\n\n"
            f"URL: {URL}\n"
            f"Target Element ID: {TARGET_ELEMENT_ID}\n"
            f"Time of Detection: {timestamp}\n\n"
            f"Previous Hash: {details['previous_hash']}\n"
            f"New Hash: {new_hash}\n\n"
            f"Please check the page for updates."
        )

        if EMAIL_NOTIFICATIONS_ENABLED:
            if EMAIL_RECIPIENTS:
                self._send_email_notification(subject, body, EMAIL_RECIPIENTS)
            else:
                logger.warning("Email notifications enabled but no recipients configured.")

    def check_website_for_changes(self) -> None:
        """
        Perform a single check of the website for content changes.

        Fetches content, extracts the target, calculates hash, and compares.
        Updates `self.previous_content_hash`.
        """
        logger.info("Checking website for content changes...", page_url=URL, target_id=TARGET_ELEMENT_ID)
        html = self._fetch_content(URL)
        current_content_str = self._extract_target_content(html, TARGET_ELEMENT_ID)
        current_hash = self._calculate_hash(current_content_str)

        if self.previous_content_hash is None:
            logger.info(
                "Initial content check complete or content re-established.",
                current_hash=current_hash,
                target_id=TARGET_ELEMENT_ID,
            )
            self.previous_content_hash = current_hash
        elif current_hash != self.previous_content_hash:
            self._notify_content_change(new_hash=current_hash, old_hash=self.previous_content_hash)
            self.previous_content_hash = current_hash
        else:
            logger.info("No change detected in content.", current_hash=current_hash)

    @staticmethod
    def _get_current_schedule_type() -> str:
        """
        Determine if the current local time falls within peak or off-peak hours.

        Returns
        -------
        str
            "peak" or "offpeak".
        """
        now_local_time = datetime.datetime.now().time()
        peak_start = datetime.time(PEAK_START_HOUR, 0)
        peak_end = datetime.time(PEAK_END_HOUR, 0)

        if peak_start <= now_local_time < peak_end:
            return "peak"
        return "offpeak"

    def manage_website_check_schedule(self) -> None:
        """
        Adjust the website checking schedule based on current time.

        Updates `self.current_job` and `self.current_schedule_type`.
        If it's the first schedule setup and no baseline hash exists,
        an initial check is performed.
        """
        required_type = self._get_current_schedule_type()

        if self.current_job is None or required_type != self.current_schedule_type:
            if self.current_job:
                schedule.cancel_job(self.current_job)
                logger.info("Cancelled previous check schedule.", cancelled_schedule_type=self.current_schedule_type)

            job_details: dict[str, Any] = {"type": required_type}

            if required_type == "peak":
                min_int, max_int = PEAK_INTERVAL_MIN, PEAK_INTERVAL_MAX
                job_details["min_interval_sec"] = min_int
                job_details["max_interval_sec"] = max_int
                self.current_job = schedule.every(min_int).to(max_int).seconds.do(self.check_website_for_changes)
            else:
                min_int, max_int = OFFPEAK_INTERVAL_MIN, OFFPEAK_INTERVAL_MAX
                job_details["min_interval_sec"] = min_int
                job_details["max_interval_sec"] = max_int
                self.current_job = schedule.every(min_int).to(max_int).seconds.do(self.check_website_for_changes)

            logger.info("Scheduled new website check job.", **job_details)
            self.current_schedule_type = required_type

            if self.previous_content_hash is None:
                logger.info(
                    "Performing initial website check immediately after (re)scheduling as no baseline hash exists."
                )
                self.check_website_for_changes()

    def run(self) -> None:
        """
        Start and run the website monitoring process.

        Sets up the initial schedule and enters a loop to run pending
        scheduled tasks. Handles graceful shutdown.
        """
        logger.info(
            "Starting Gamers Nexus Garage Sale Monitor.",
            version="1.5-notifications",
            pid=os.getpid(),
            monitoring_url=URL,
            target_element=TARGET_ELEMENT_ID,
        )

        self.manage_website_check_schedule()
        schedule.every(1).minute.do(self.manage_website_check_schedule)

        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Script terminated by user (KeyboardInterrupt).")
        except Exception as e:
            logger.error(
                "An unexpected critical error occurred in the main monitoring loop.",
                error_message=str(e),
                exc_info=True,
            )
        finally:
            logger.info("Stopping Gamers Nexus Garage Sale Monitor.")


def main() -> None:
    """Entry point for the script. Creates a WebsiteMonitor instance and runs it."""
    monitor = WebsiteMonitor()
    monitor.run()


if __name__ == "__main__":
    main()
