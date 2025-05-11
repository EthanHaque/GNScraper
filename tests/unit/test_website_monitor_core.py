# src/scraper/website_monitor.py
# (Assuming other imports and constants are already defined as in your provided script)

# ... (other imports and constants like URL, TARGET_ELEMENT_ID, etc.)
# ... (logging_config setup and logger definition)


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
        Extract the combined string representation of all target HTML elements.

        If multiple elements share the same ID, their string representations
        are concatenated. This allows detection of changes if any of these
        elements change or if the number of such elements changes.

        Parameters
        ----------
        html_content : Optional[str]
            The HTML content of the page as a string.
        element_id : str
            The ID of the HTML elements to extract.

        Returns
        -------
        Optional[str]
            The combined string representation of all found target elements,
            separated by newlines. Returns None if no elements are found or
            if html_content is None.
        """
        if not html_content:
            logger.debug("HTML content is None, cannot extract target content.")
            return None
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            # MODIFIED: Use find_all to get all elements with the given ID
            target_elements = soup.find_all(id=element_id)

            if target_elements:
                logger.debug(
                    f"{len(target_elements)} target element(s) found.", target_id=element_id, count=len(target_elements)
                )
                # Concatenate the string representation of all found elements
                # Using a newline separator for clarity if one were to inspect the combined string,
                # though for hashing, any consistent concatenation works.
                return "\n".join(str(element) for element in target_elements)

            logger.warning(
                "Target element not found in HTML content.",
                target_id=element_id,
                page_url=URL,  # URL is a module-level constant
            )
            return None
        except Exception as e:
            logger.error(
                "Failed to parse HTML or extract element(s).", target_id=element_id, error_message=str(e), exc_info=True
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
        (Implementation as provided by user)
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
            logger.error("SMTP authentication failed. Check SMTP_USER/SMTP_PASSWORD.", error=str(e), exc_info=False)
        except smtplib.SMTPServerDisconnected:
            logger.error("SMTP server disconnected unexpectedly.", exc_info=True)
        except smtplib.SMTPException as e:
            logger.error("Failed to send email notification due to SMTP error.", error=str(e), exc_info=True)
        except Exception as e:  # Catch other potential errors like socket.gaierror
            logger.error("An unexpected error occurred while sending email.", error=str(e), exc_info=True)

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
            else:  # offpeak
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
        """
        logger.info(
            "Starting Gamers Nexus Garage Sale Monitor.",
            version="1.1.1-multi-element",  # Example version update
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


# ... (main function and if __name__ == "__main__": block remain the same)
def main() -> None:
    """Entry point for the script. Creates a WebsiteMonitor instance and runs it."""
    monitor = WebsiteMonitor()
    monitor.run()


if __name__ == "__main__":
    main()
