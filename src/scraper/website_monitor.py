"""
Monitors a specific webpage for changes in the content of a target HTML element.

This script periodically fetches a webpage, extracts content from a designated
HTML element, and compares its hash to a previously stored hash. If a change
is detected, a notification is sent. The checking frequency adjusts based
on predefined peak and off-peak hours.
"""

import datetime
import hashlib
import os
import time
from typing import Any

import requests
import schedule
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from scraper import logging_config

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

        The session is configured with a common User-Agent and a retry strategy
        for GET requests that encounter specific HTTP status codes or transient
        network issues.

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

        This method is static as it doesn't depend on instance state, only on
        its inputs and module constants for logging context.

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

        Static method as it's a pure function of its input.

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

    def _notify_content_change(self, new_hash: str, old_hash: str | None) -> None:
        """
        Log a notification that the monitored content has changed.

        Parameters
        ----------
        new_hash : str
            The new hash of the content.
        old_hash : Optional[str]
            The previous hash of the content.
        """
        logger.info(
            "CHANGE DETECTED: Monitored content has updated.",
            previous_hash=old_hash if old_hash else "N/A (was not found or initial)",
            new_hash=new_hash,
            page_url=URL,
            element_id=TARGET_ELEMENT_ID,
        )

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

        Static method as it does not depend on instance state.

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
            version="1.4-class-based",
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
