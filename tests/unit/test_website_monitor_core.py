# tests/unit/test_website_monitor_core.py
"""
Unit tests for the core functionalities of the WebsiteMonitor class.

This suite tests session creation, content fetching, parsing, hashing,
scheduling logic, and the main change detection workflow, excluding
direct tests of notification sending mechanisms (which are in a separate file).
"""

import datetime
import hashlib
from unittest.mock import MagicMock, Mock, ANY

import pytest
import requests  # For requests.exceptions and using the original Session for spec
import schedule  # For schedule.clear()

# Import the module from your package
from scraper import website_monitor


@pytest.fixture(autouse=True)
def clear_schedule_before_each_test():
    """Ensures the schedule is clear before and after each test."""
    schedule.clear()
    yield
    schedule.clear()


@pytest.fixture
def mock_session(mocker):
    """Fixture to provide a mocked requests.Session instance."""
    session = Mock(spec=requests.Session)  # Use original requests.Session for spec
    session.headers = {}  # Mock the headers attribute as it's updated
    session.mount = Mock()
    return session


@pytest.fixture
def monitor_instance(mocker, mock_session) -> website_monitor.WebsiteMonitor:
    """
    Provides a WebsiteMonitor instance with its _create_session_with_retries
    method patched to return a predefined mock session.
    This means monitor.session will be the mock_session.
    """
    # Patch the static method on the class
    mocker.patch("scraper.website_monitor.WebsiteMonitor._create_session_with_retries", return_value=mock_session)
    monitor = website_monitor.WebsiteMonitor()
    return monitor


# --- Tests for Static/Helper Methods ---


def test_create_session_with_retries(mocker):
    """Test the static _create_session_with_retries method."""
    # Patch external dependencies used by _create_session_with_retries
    # This mock_requests_session_cls is what website_monitor._create_session_with_retries will see and use
    mock_requests_session_cls_in_module = mocker.patch("scraper.website_monitor.requests.Session")
    mock_http_adapter_cls = mocker.patch("scraper.website_monitor.HTTPAdapter")
    mock_retry_cls = mocker.patch("scraper.website_monitor.Retry")

    # This mock_session_instance is the one we expect _create_session_with_retries to return
    # after it calls the (mocked) scraper.website_monitor.requests.Session()
    expected_returned_session_instance = Mock(spec=requests.sessions.Session)  # Use original requests.Session for spec
    expected_returned_session_instance.headers = Mock()  # Ensure headers attribute exists
    mock_requests_session_cls_in_module.return_value = expected_returned_session_instance

    # Call the method under test
    actual_session = website_monitor.WebsiteMonitor._create_session_with_retries()

    assert actual_session == expected_returned_session_instance
    mock_requests_session_cls_in_module.assert_called_once()  # Check that the patched Session constructor was called
    mock_retry_cls.assert_called_once_with(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    mock_http_adapter_cls.assert_called_once_with(max_retries=mock_retry_cls.return_value)
    # Assert calls on the session instance that was returned by the mocked Session constructor
    expected_returned_session_instance.mount.assert_any_call("http://", mock_http_adapter_cls.return_value)
    expected_returned_session_instance.mount.assert_any_call("https://", mock_http_adapter_cls.return_value)
    expected_returned_session_instance.headers.update.assert_called_once_with(
        {"User-Agent": website_monitor.USER_AGENT}
    )


def test_extract_target_content_found(mocker):
    """Tests _extract_target_content when the element is found."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    html = (
        f"<html><body><div id='{website_monitor.TARGET_ELEMENT_ID}'>Expected Text <p>More</p></div>Extra</body></html>"
    )
    expected_str = f'<div id="{website_monitor.TARGET_ELEMENT_ID}">Expected Text <p>More</p></div>'

    # Call as a static method
    content = website_monitor.WebsiteMonitor._extract_target_content(html, website_monitor.TARGET_ELEMENT_ID)

    assert content == expected_str
    mock_logger.debug.assert_any_call(
        "1 target element(s) found.", target_id=website_monitor.TARGET_ELEMENT_ID, count=1
    )


def test_extract_target_content_not_found(mocker):
    """Tests _extract_target_content when the element is not found."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    html = "<html><body><div>Nothing here</div></body></html>"

    content = website_monitor.WebsiteMonitor._extract_target_content(html, website_monitor.TARGET_ELEMENT_ID)

    assert content is None
    mock_logger.warning.assert_called_once_with(
        "Target element not found in HTML content.",
        target_id=website_monitor.TARGET_ELEMENT_ID,
        page_url=website_monitor.URL,  # URL is a module constant
    )


def test_extract_target_content_empty_or_invalid_html(mocker):
    """Tests _extract_target_content with None or malformed HTML."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    # Test 1: None input
    assert website_monitor.WebsiteMonitor._extract_target_content(None, website_monitor.TARGET_ELEMENT_ID) is None
    mock_logger.debug.assert_any_call("HTML content is None, cannot extract target content.")
    mock_logger.warning.assert_not_called()  # No warning for None input
    mock_logger.error.assert_not_called()  # No error for None input
    mock_logger.reset_mock()  # Reset for the next part of the test

    # Test 2: Malformed HTML (BeautifulSoup is lenient, might lead to "not found")
    malformed_html = "<html><body><div id='productList'"  # Incomplete attribute
    content = website_monitor.WebsiteMonitor._extract_target_content(malformed_html, website_monitor.TARGET_ELEMENT_ID)
    assert content is None
    # Expect a warning because the element (due to malformed ID) won't be found
    mock_logger.warning.assert_called_once_with(
        "Target element not found in HTML content.",
        target_id=website_monitor.TARGET_ELEMENT_ID,
        page_url=website_monitor.URL,
    )
    mock_logger.error.assert_not_called()  # BeautifulSoup usually doesn't error on this


def test_calculate_hash():
    """Tests the static _calculate_hash method."""
    content1 = "Hello World"
    hash1 = website_monitor.WebsiteMonitor._calculate_hash(content1)

    assert hash1 == hashlib.sha256(content1.encode("utf-8")).hexdigest()
    assert website_monitor.WebsiteMonitor._calculate_hash(content1) == hash1  # Consistency
    assert website_monitor.WebsiteMonitor._calculate_hash("Other Content") != hash1
    assert website_monitor.WebsiteMonitor._calculate_hash(None) == "element_not_found_or_empty"


@pytest.mark.parametrize(
    "current_time_tuple, expected_type",
    [
        ((10, 0, 0), "peak"),
        ((3, 0, 0), "offpeak"),
        ((22, 0, 0), "offpeak"),
        ((website_monitor.PEAK_START_HOUR, 0, 0), "peak"),
        ((website_monitor.PEAK_END_HOUR, 0, 0), "offpeak"),  # At 21:00, it's off-peak
        ((website_monitor.PEAK_END_HOUR - 1, 59, 59), "peak"),  # Just before off-peak
    ],
)
def test_get_current_schedule_type_parametrized(mocker, current_time_tuple, expected_type):
    """Tests the static _get_current_schedule_type method with various times."""
    # Patch datetime.datetime where it's used inside scraper.website_monitor
    mock_dt_datetime = mocker.patch("scraper.website_monitor.datetime.datetime")
    mock_dt_datetime.now.return_value.time.return_value = datetime.time(*current_time_tuple)

    assert website_monitor.WebsiteMonitor._get_current_schedule_type() == expected_type


# --- Tests for Instance Methods (using monitor_instance fixture) ---


def test_fetch_content_success_on_instance(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests _fetch_content success using a monitor instance."""
    # monitor_instance.session is already the mock_session from the fixture
    mock_logger = mocker.patch("scraper.website_monitor.logger")  # Module logger

    mock_response = Mock(spec=requests.Response)  # Use spec for better response mocking
    mock_response.text = "<html>Test Content</html>"
    mock_response.status_code = 200  # Needed for raise_for_status
    mock_response.raise_for_status = Mock()  # Mock this method

    monitor_instance.session.get.return_value = mock_response

    html = monitor_instance._fetch_content(website_monitor.URL)

    assert html == "<html>Test Content</html>"
    monitor_instance.session.get.assert_called_once_with(website_monitor.URL, timeout=website_monitor.REQUEST_TIMEOUT)
    mock_response.raise_for_status.assert_called_once()
    mock_logger.error.assert_not_called()


def test_fetch_content_http_error_on_instance(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests _fetch_content with an HTTP error using a monitor instance."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    http_error_instance = requests.exceptions.HTTPError("Test HTTP Error")

    # Configure the mock response to raise an error when raise_for_status is called
    mock_response = Mock(spec=requests.Response)
    mock_response.raise_for_status.side_effect = http_error_instance
    monitor_instance.session.get.return_value = mock_response

    html = monitor_instance._fetch_content(website_monitor.URL)
    assert html is None
    mock_logger.error.assert_called_once_with(
        "Failed to fetch URL content.",
        page_url=website_monitor.URL,
        error_message=str(http_error_instance),  # Error message comes from the exception
        exc_info=False,
    )


def test_check_website_initial_run(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests the first run of check_website_for_changes."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    # Mock helper methods called by check_website_for_changes
    mocker.patch.object(monitor_instance, "_fetch_content", return_value="dummy_html_content")
    # _extract_target_content and _calculate_hash are static, so patch them on the class
    mocker.patch(
        "scraper.website_monitor.WebsiteMonitor._extract_target_content", return_value="dummy_extracted_content"
    )
    mocker.patch("scraper.website_monitor.WebsiteMonitor._calculate_hash", return_value="new_hash_123")

    assert monitor_instance.previous_content_hash is None  # Initial state
    monitor_instance.check_website_for_changes()

    monitor_instance._fetch_content.assert_called_once_with(website_monitor.URL)
    website_monitor.WebsiteMonitor._extract_target_content.assert_called_once_with(
        "dummy_html_content", website_monitor.TARGET_ELEMENT_ID
    )
    website_monitor.WebsiteMonitor._calculate_hash.assert_called_once_with("dummy_extracted_content")

    mock_logger.info.assert_any_call(
        "Initial content check complete or content re-established.",
        current_hash="new_hash_123",
        target_id=website_monitor.TARGET_ELEMENT_ID,
    )
    assert monitor_instance.previous_content_hash == "new_hash_123"


def test_check_website_change_detected(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests change detection in check_website_for_changes."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    # Mock the notification method to prevent actual notifications and allow assertion
    mock_notify_method = mocker.patch.object(monitor_instance, "_notify_content_change")

    monitor_instance.previous_content_hash = "old_hash_000"  # Set prior state

    mocker.patch.object(monitor_instance, "_fetch_content", return_value="new_html")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._extract_target_content", return_value="new_content")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._calculate_hash", return_value="new_hash_456")

    monitor_instance.check_website_for_changes()

    # _notify_content_change should have been called
    mock_notify_method.assert_called_once_with(new_hash="new_hash_456", old_hash="old_hash_000")
    assert monitor_instance.previous_content_hash == "new_hash_456"


def test_check_website_no_change(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests behavior of check_website_for_changes when no change occurs."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_notify_method = mocker.patch.object(monitor_instance, "_notify_content_change")

    monitor_instance.previous_content_hash = "same_hash_789"

    mocker.patch.object(monitor_instance, "_fetch_content", return_value="same_html")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._extract_target_content", return_value="same_content")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._calculate_hash", return_value="same_hash_789")

    monitor_instance.check_website_for_changes()

    mock_logger.info.assert_any_call("No change detected in content.", current_hash="same_hash_789")
    mock_notify_method.assert_not_called()  # Ensure notifications were NOT triggered
    assert monitor_instance.previous_content_hash == "same_hash_789"


def test_manage_schedule_initial_peak_and_first_check(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests initial schedule setup during peak hours and the immediate first check."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    # _get_current_schedule_type is static
    mocker.patch("scraper.website_monitor.WebsiteMonitor._get_current_schedule_type", return_value="peak")
    # Mock the method that would be called by the scheduler and potentially by manage_schedule itself
    mock_check_changes_method = mocker.patch.object(monitor_instance, "check_website_for_changes")

    assert monitor_instance.previous_content_hash is None  # Key for triggering initial check

    mock_job_object = MagicMock()
    # Configure the mock for the chained calls of schedule.every()...
    (
        mock_schedule_lib.every(website_monitor.PEAK_INTERVAL_MIN)
        .to(website_monitor.PEAK_INTERVAL_MAX)
        .seconds.do.return_value
    ) = mock_job_object

    monitor_instance.manage_website_check_schedule()

    # Verify the correct schedule was set
    mock_schedule_lib.every(website_monitor.PEAK_INTERVAL_MIN).to(
        website_monitor.PEAK_INTERVAL_MAX
    ).seconds.do.assert_called_once_with(monitor_instance.check_website_for_changes)

    mock_logger.info.assert_any_call(
        "Scheduled new website check job.",
        type="peak",
        min_interval_sec=website_monitor.PEAK_INTERVAL_MIN,
        max_interval_sec=website_monitor.PEAK_INTERVAL_MAX,
    )
    mock_logger.info.assert_any_call(
        "Performing initial website check immediately after (re)scheduling as no baseline hash exists."
    )
    mock_check_changes_method.assert_called_once()  # Assert the direct call

    assert monitor_instance.current_job == mock_job_object
    assert monitor_instance.current_schedule_type == "peak"


def test_manage_schedule_change_to_offpeak(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests schedule transition from peak to off-peak."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._get_current_schedule_type", return_value="offpeak")
    mock_check_changes_method = mocker.patch.object(monitor_instance, "check_website_for_changes")

    # Setup initial state as if a peak job was running
    initial_mock_job = MagicMock()
    monitor_instance.current_job = initial_mock_job
    monitor_instance.current_schedule_type = "peak"
    monitor_instance.previous_content_hash = "some_initial_hash"  # Indicate not the very first run

    new_mock_job_object = MagicMock()
    (
        mock_schedule_lib.every(website_monitor.OFFPEAK_INTERVAL_MIN)
        .to(website_monitor.OFFPEAK_INTERVAL_MAX)
        .seconds.do.return_value
    ) = new_mock_job_object

    monitor_instance.manage_website_check_schedule()

    mock_schedule_lib.cancel_job.assert_called_once_with(initial_mock_job)
    mock_logger.info.assert_any_call("Cancelled previous check schedule.", cancelled_schedule_type="peak")

    mock_schedule_lib.every(website_monitor.OFFPEAK_INTERVAL_MIN).to(
        website_monitor.OFFPEAK_INTERVAL_MAX
    ).seconds.do.assert_called_once_with(monitor_instance.check_website_for_changes)
    mock_logger.info.assert_any_call(
        "Scheduled new website check job.",
        type="offpeak",
        min_interval_sec=website_monitor.OFFPEAK_INTERVAL_MIN,
        max_interval_sec=website_monitor.OFFPEAK_INTERVAL_MAX,
    )

    assert monitor_instance.current_job == new_mock_job_object
    assert monitor_instance.current_schedule_type == "offpeak"
    mock_check_changes_method.assert_not_called()  # Not called if previous_content_hash exists


def test_manage_schedule_no_change_needed(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests manage_schedule when no change in schedule type is required."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._get_current_schedule_type", return_value="peak")

    # Setup as if a peak job is already correctly scheduled
    mock_existing_job = MagicMock()
    monitor_instance.current_job = mock_existing_job
    monitor_instance.current_schedule_type = "peak"
    monitor_instance.previous_content_hash = "some_hash"  # Not first run

    monitor_instance.manage_website_check_schedule()

    mock_schedule_lib.cancel_job.assert_not_called()
    # Ensure no NEW job scheduling calls like every().to()... were made
    mock_schedule_lib.every().to().seconds.do.assert_not_called()

    scheduled_new_job_logged = False
    if mock_logger.info.call_args_list:  # Check if any info logs were made
        for call_args_tuple in mock_logger.info.call_args_list:
            # Access positional arguments via .args
            if call_args_tuple.args and call_args_tuple.args[0] == "Scheduled new website check job.":
                scheduled_new_job_logged = True
                break
    assert not scheduled_new_job_logged

    assert monitor_instance.current_job == mock_existing_job  # Job remains the same
    assert monitor_instance.current_schedule_type == "peak"  # Schedule type remains


def test_website_monitor_init(mocker):
    """Tests the __init__ method of WebsiteMonitor."""
    # Patch the static method _create_session_with_retries called by __init__
    mock_create_session = mocker.patch("scraper.website_monitor.WebsiteMonitor._create_session_with_retries")
    # For the spec of the returned session instance, use the original requests.Session
    mock_session_instance = Mock(spec=requests.Session)
    mock_create_session.return_value = mock_session_instance

    monitor = website_monitor.WebsiteMonitor()

    mock_create_session.assert_called_once()
    assert monitor.session == mock_session_instance
    assert monitor.previous_content_hash is None
    assert monitor.current_job is None
    assert monitor.current_schedule_type is None
    # Optionally, assert that the init debug log was made
    # mocker.patch('scraper.website_monitor.logger').debug.assert_called_with("WebsiteMonitor instance initialized.")


def test_extract_target_content_should_combine_multiple_elements(mocker):
    """
    Tests that _extract_target_content combines content from all elements
    if multiple share the same target ID.
    This test EXPECTS the new behavior (using find_all and concatenating).
    """
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    test_id = "productList"  # Using the actual TARGET_ELEMENT_ID for this test
    html_doc_with_multiple = f"""
    <html><body>
        <div id="{test_id}">First item content.</div>
        <p>Some other paragraph.</p>
        <div id="{test_id}">Second item <b>bold</b> content.</div>
        <div id="anotherId">Not this one.</div>
        <div id="{test_id}">Third item.</div>
    </body></html>
    """

    # Expected output IF the implementation uses find_all and joins strings
    # (assuming a newline separator as implemented in the proposed solution)
    expected_elem1 = f'<div id="{test_id}">First item content.</div>'
    expected_elem2 = f'<div id="{test_id}">Second item <b>bold</b> content.</div>'
    expected_elem3 = f'<div id="{test_id}">Third item.</div>'
    expected_combined_content = "\n".join([expected_elem1, expected_elem2, expected_elem3])

    # This call will use the CURRENT implementation of _extract_target_content
    # from your scraper.website_monitor module
    actual_content = website_monitor.WebsiteMonitor._extract_target_content(html_doc_with_multiple, test_id)

    # This assertion will FAIL until _extract_target_content is updated
    # to use find_all and join the results.
    assert actual_content == expected_combined_content, "Test expects combined content of multiple elements"
