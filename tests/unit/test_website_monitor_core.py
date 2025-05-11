"""Unit tests for the core functionalities of the WebsiteMonitor class."""

import datetime
import hashlib
from unittest.mock import MagicMock, Mock

import pytest
import requests
import schedule

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
    session = Mock(spec=requests.Session)
    session.headers = {}
    session.mount = Mock()
    return session


@pytest.fixture
def monitor_instance(mocker, mock_session) -> website_monitor.WebsiteMonitor:
    """
    Provides a WebsiteMonitor instance with its _create_session_with_retries
    method patched to return a predefined mock session.
    This means monitor.session will be the mock_session.
    """
    mocker.patch("scraper.website_monitor.WebsiteMonitor._create_session_with_retries", return_value=mock_session)
    monitor = website_monitor.WebsiteMonitor()
    return monitor


def test_create_session_with_retries(mocker):
    """Test the static _create_session_with_retries method."""
    mock_requests_session_cls_in_module = mocker.patch("scraper.website_monitor.requests.Session")
    mock_http_adapter_cls = mocker.patch("scraper.website_monitor.HTTPAdapter")
    mock_retry_cls = mocker.patch("scraper.website_monitor.Retry")

    expected_returned_session_instance = Mock(spec=requests.sessions.Session)
    expected_returned_session_instance.headers = Mock()
    mock_requests_session_cls_in_module.return_value = expected_returned_session_instance

    actual_session = website_monitor.WebsiteMonitor._create_session_with_retries()

    assert actual_session == expected_returned_session_instance
    mock_requests_session_cls_in_module.assert_called_once()
    mock_retry_cls.assert_called_once_with(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    mock_http_adapter_cls.assert_called_once_with(max_retries=mock_retry_cls.return_value)
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
        page_url=website_monitor.URL,
    )


def test_extract_target_content_empty_or_invalid_html(mocker):
    """Tests _extract_target_content with None or malformed HTML."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    # Test 1: None input
    assert website_monitor.WebsiteMonitor._extract_target_content(None, website_monitor.TARGET_ELEMENT_ID) is None
    mock_logger.debug.assert_any_call("HTML content is None, cannot extract target content.")
    mock_logger.warning.assert_not_called()
    mock_logger.error.assert_not_called()
    mock_logger.reset_mock()

    # Test 2: Malformed HTML (BeautifulSoup is lenient, might lead to "not found")
    malformed_html = "<html><body><div id='productList'"
    content = website_monitor.WebsiteMonitor._extract_target_content(malformed_html, website_monitor.TARGET_ELEMENT_ID)
    assert content is None
    # Expect a warning because the element (due to malformed ID) won't be found
    mock_logger.warning.assert_called_once_with(
        "Target element not found in HTML content.",
        target_id=website_monitor.TARGET_ELEMENT_ID,
        page_url=website_monitor.URL,
    )
    mock_logger.error.assert_not_called()


def test_calculate_hash():
    """Tests the static _calculate_hash method."""
    content1 = "Hello World"
    hash1 = website_monitor.WebsiteMonitor._calculate_hash(content1)

    assert hash1 == hashlib.sha256(content1.encode("utf-8")).hexdigest()
    assert website_monitor.WebsiteMonitor._calculate_hash(content1) == hash1
    assert website_monitor.WebsiteMonitor._calculate_hash("Other Content") != hash1
    assert website_monitor.WebsiteMonitor._calculate_hash(None) == "element_not_found_or_empty"


@pytest.mark.parametrize(
    "current_time_tuple, expected_type",
    [
        ((10, 0, 0), "peak"),
        ((3, 0, 0), "offpeak"),
        ((22, 0, 0), "offpeak"),
        ((website_monitor.PEAK_START_HOUR, 0, 0), "peak"),
        ((website_monitor.PEAK_END_HOUR, 0, 0), "offpeak"),
        ((website_monitor.PEAK_END_HOUR - 1, 59, 59), "peak"),
    ],
)
def test_get_current_schedule_type_parametrized(mocker, current_time_tuple, expected_type):
    """Tests the static _get_current_schedule_type method with various times."""
    mock_dt_datetime = mocker.patch("scraper.website_monitor.datetime.datetime")
    mock_dt_datetime.now.return_value.time.return_value = datetime.time(*current_time_tuple)

    assert website_monitor.WebsiteMonitor._get_current_schedule_type() == expected_type


def test_fetch_content_success_on_instance(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests _fetch_content success using a monitor instance."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    mock_response = Mock(spec=requests.Response)
    mock_response.text = "<html>Test Content</html>"
    mock_response.status_code = 200
    mock_response.raise_for_status = Mock()

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

    mock_response = Mock(spec=requests.Response)
    mock_response.raise_for_status.side_effect = http_error_instance
    monitor_instance.session.get.return_value = mock_response

    html = monitor_instance._fetch_content(website_monitor.URL)
    assert html is None
    mock_logger.error.assert_called_once_with(
        "Failed to fetch URL content.",
        page_url=website_monitor.URL,
        error_message=str(http_error_instance),
        exc_info=False,
    )


def test_check_website_initial_run(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests the first run of check_website_for_changes."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    mocker.patch.object(monitor_instance, "_fetch_content", return_value="dummy_html_content")
    mocker.patch(
        "scraper.website_monitor.WebsiteMonitor._extract_target_content", return_value="dummy_extracted_content"
    )
    mocker.patch("scraper.website_monitor.WebsiteMonitor._calculate_hash", return_value="new_hash_123")

    assert monitor_instance.previous_content_hash is None
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
    mock_notify_method = mocker.patch.object(monitor_instance, "_notify_content_change")

    monitor_instance.previous_content_hash = "old_hash_000"

    mocker.patch.object(monitor_instance, "_fetch_content", return_value="new_html")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._extract_target_content", return_value="new_content")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._calculate_hash", return_value="new_hash_456")

    monitor_instance.check_website_for_changes()

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
    mock_notify_method.assert_not_called()
    assert monitor_instance.previous_content_hash == "same_hash_789"


def test_manage_schedule_initial_peak_and_first_check(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests initial schedule setup during peak hours and the immediate first check."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._get_current_schedule_type", return_value="peak")
    mock_check_changes_method = mocker.patch.object(monitor_instance, "check_website_for_changes")

    assert monitor_instance.previous_content_hash is None

    mock_job_object = MagicMock()
    (
        mock_schedule_lib.every(website_monitor.PEAK_INTERVAL_MIN)
        .to(website_monitor.PEAK_INTERVAL_MAX)
        .seconds.do.return_value
    ) = mock_job_object

    monitor_instance.manage_website_check_schedule()

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
    mock_check_changes_method.assert_called_once()

    assert monitor_instance.current_job == mock_job_object
    assert monitor_instance.current_schedule_type == "peak"


def test_manage_schedule_change_to_offpeak(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests schedule transition from peak to off-peak."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._get_current_schedule_type", return_value="offpeak")
    mock_check_changes_method = mocker.patch.object(monitor_instance, "check_website_for_changes")

    initial_mock_job = MagicMock()
    monitor_instance.current_job = initial_mock_job
    monitor_instance.current_schedule_type = "peak"
    monitor_instance.previous_content_hash = "some_initial_hash"

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
    mock_check_changes_method.assert_not_called()


def test_manage_schedule_no_change_needed(mocker, monitor_instance: website_monitor.WebsiteMonitor):
    """Tests manage_schedule when no change in schedule type is required."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._get_current_schedule_type", return_value="peak")

    mock_existing_job = MagicMock()
    monitor_instance.current_job = mock_existing_job
    monitor_instance.current_schedule_type = "peak"
    monitor_instance.previous_content_hash = "some_hash"

    monitor_instance.manage_website_check_schedule()

    mock_schedule_lib.cancel_job.assert_not_called()
    mock_schedule_lib.every().to().seconds.do.assert_not_called()

    scheduled_new_job_logged = False
    if mock_logger.info.call_args_list:
        for call_args_tuple in mock_logger.info.call_args_list:
            if call_args_tuple.args and call_args_tuple.args[0] == "Scheduled new website check job.":
                scheduled_new_job_logged = True
                break
    assert not scheduled_new_job_logged

    assert monitor_instance.current_job == mock_existing_job
    assert monitor_instance.current_schedule_type == "peak"


def test_website_monitor_init(mocker):
    """Tests the __init__ method of WebsiteMonitor."""
    mock_create_session = mocker.patch("scraper.website_monitor.WebsiteMonitor._create_session_with_retries")
    mock_session_instance = Mock(spec=requests.Session)
    mock_create_session.return_value = mock_session_instance

    monitor = website_monitor.WebsiteMonitor()

    mock_create_session.assert_called_once()
    assert monitor.session == mock_session_instance
    assert monitor.previous_content_hash is None
    assert monitor.current_job is None
    assert monitor.current_schedule_type is None


def test_extract_target_content_should_combine_multiple_elements(mocker):
    """
    Tests that _extract_target_content combines content from all elements
    if multiple share the same target ID.
    This test EXPECTS the new behavior (using find_all and concatenating).
    """
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    test_id = "productList"
    html_doc_with_multiple = f"""
    <html><body>
        <div id="{test_id}">First item content.</div>
        <p>Some other paragraph.</p>
        <div id="{test_id}">Second item <b>bold</b> content.</div>
        <div id="anotherId">Not this one.</div>
        <div id="{test_id}">Third item.</div>
    </body></html>
    """

    expected_elem1 = f'<div id="{test_id}">First item content.</div>'
    expected_elem2 = f'<div id="{test_id}">Second item <b>bold</b> content.</div>'
    expected_elem3 = f'<div id="{test_id}">Third item.</div>'
    expected_combined_content = "\n".join([expected_elem1, expected_elem2, expected_elem3])

    actual_content = website_monitor.WebsiteMonitor._extract_target_content(html_doc_with_multiple, test_id)
    assert actual_content == expected_combined_content, "Test expects combined content of multiple elements"
