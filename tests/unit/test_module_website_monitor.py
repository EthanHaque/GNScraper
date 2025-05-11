import datetime
import hashlib
from unittest.mock import MagicMock, Mock

import pytest
import requests
import schedule

from scraper import website_monitor


@pytest.fixture(autouse=True)
def clear_schedule_before_each_test():
    """Ensures the schedule is clear before each test."""
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
def monitor_with_mock_session(mocker, mock_session):
    """
    Provides a WebsiteMonitor instance with its _create_session_with_retries
    method patched to return a predefined mock session.
    This means monitor.session will be mock_session.
    """
    mocker.patch("scraper.website_monitor.WebsiteMonitor._create_session_with_retries", return_value=mock_session)
    monitor = website_monitor.WebsiteMonitor()
    return monitor


def test_create_session_with_retries(mocker):
    """Test the static _create_session_with_retries method."""
    mock_requests_session_cls = mocker.patch("scraper.website_monitor.requests.Session")
    mock_http_adapter_cls = mocker.patch("scraper.website_monitor.HTTPAdapter")
    mock_retry_cls = mocker.patch("scraper.website_monitor.Retry")

    mock_session_instance = Mock()
    mock_requests_session_cls.return_value = mock_session_instance

    session = website_monitor.WebsiteMonitor._create_session_with_retries()

    assert session == mock_session_instance
    mock_retry_cls.assert_called_once_with(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    mock_http_adapter_cls.assert_called_once_with(max_retries=mock_retry_cls.return_value)
    mock_session_instance.mount.assert_any_call("http://", mock_http_adapter_cls.return_value)
    mock_session_instance.mount.assert_any_call("https://", mock_http_adapter_cls.return_value)
    mock_session_instance.headers.update.assert_called_once_with({"User-Agent": website_monitor.USER_AGENT})


def test_extract_target_content_found(mocker):
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    html = (
        f"<html><body><div id='{website_monitor.TARGET_ELEMENT_ID}'>Expected Text <p>More</p></div>Extra</body></html>"
    )
    expected_str = f'<div id="{website_monitor.TARGET_ELEMENT_ID}">Expected Text <p>More</p></div>'
    content = website_monitor.WebsiteMonitor._extract_target_content(html, website_monitor.TARGET_ELEMENT_ID)
    assert content == expected_str
    mock_logger.debug.assert_any_call("Target element found.", target_id=website_monitor.TARGET_ELEMENT_ID)


def test_extract_target_content_not_found(mocker):
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
    mock_logger.warning.assert_called_once_with(
        "Target element not found in HTML content.",
        target_id=website_monitor.TARGET_ELEMENT_ID,
        page_url=website_monitor.URL,
    )
    mock_logger.error.assert_not_called()


def test_calculate_hash():
    content1 = "Hello World"
    hash1 = website_monitor.WebsiteMonitor._calculate_hash(content1)
    assert hash1 == hashlib.sha256(content1.encode("utf-8")).hexdigest()
    assert website_monitor.WebsiteMonitor._calculate_hash(content1) == hash1
    assert website_monitor.WebsiteMonitor._calculate_hash("Other Content") != hash1
    assert website_monitor.WebsiteMonitor._calculate_hash(None) == "element_not_found_or_empty"


def test_get_current_schedule_type(mocker):
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
    def run_test(current_time_tuple, expected_type):
        mock_dt_datetime = mocker.patch("scraper.website_monitor.datetime.datetime")
        mock_dt_datetime.now.return_value.time.return_value = datetime.time(*current_time_tuple)
        assert website_monitor.WebsiteMonitor._get_current_schedule_type() == expected_type


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
    mock_dt_datetime = mocker.patch("scraper.website_monitor.datetime.datetime")
    mock_dt_datetime.now.return_value.time.return_value = datetime.time(*current_time_tuple)
    assert website_monitor.WebsiteMonitor._get_current_schedule_type() == expected_type


def test_fetch_content_success_on_instance(mocker, monitor_with_mock_session):
    monitor = monitor_with_mock_session
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    mock_response = Mock()
    mock_response.text = "<html>Test Content</html>"
    mock_response.raise_for_status = Mock()
    monitor.session.get.return_value = mock_response

    html = monitor._fetch_content(website_monitor.URL)

    assert html == "<html>Test Content</html>"
    monitor.session.get.assert_called_once_with(website_monitor.URL, timeout=website_monitor.REQUEST_TIMEOUT)
    mock_response.raise_for_status.assert_called_once()
    mock_logger.error.assert_not_called()


def test_fetch_content_http_error_on_instance(mocker, monitor_with_mock_session):
    monitor = monitor_with_mock_session
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    http_error_instance = requests.exceptions.HTTPError("Test HTTP Error")
    monitor.session.get.side_effect = http_error_instance

    html = monitor._fetch_content(website_monitor.URL)
    assert html is None
    mock_logger.error.assert_called_once_with(
        "Failed to fetch URL content.",
        page_url=website_monitor.URL,
        error_message=str(http_error_instance),
        exc_info=False,
    )


def test_check_website_initial_run(mocker, monitor_with_mock_session):
    monitor = monitor_with_mock_session
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    mocker.patch.object(monitor, "_fetch_content", return_value="dummy_html_content")
    mocker.patch(
        "scraper.website_monitor.WebsiteMonitor._extract_target_content", return_value="dummy_extracted_content"
    )
    mocker.patch("scraper.website_monitor.WebsiteMonitor._calculate_hash", return_value="new_hash_123")

    assert monitor.previous_content_hash is None
    monitor.check_website_for_changes()

    monitor._fetch_content.assert_called_once_with(website_monitor.URL)
    website_monitor.WebsiteMonitor._extract_target_content.assert_called_once_with(
        "dummy_html_content", website_monitor.TARGET_ELEMENT_ID
    )
    website_monitor.WebsiteMonitor._calculate_hash.assert_called_once_with("dummy_extracted_content")

    mock_logger.info.assert_any_call(
        "Initial content check complete or content re-established.",
        current_hash="new_hash_123",
        target_id=website_monitor.TARGET_ELEMENT_ID,
    )
    assert monitor.previous_content_hash == "new_hash_123"


def test_check_website_change_detected(mocker, monitor_with_mock_session):
    monitor = monitor_with_mock_session
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    monitor.previous_content_hash = "old_hash_000"

    mocker.patch.object(monitor, "_fetch_content", return_value="new_html")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._extract_target_content", return_value="new_content")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._calculate_hash", return_value="new_hash_456")

    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call(
        "CHANGE DETECTED: Monitored content has updated.",
        previous_hash="old_hash_000",
        new_hash="new_hash_456",
        page_url=website_monitor.URL,
        element_id=website_monitor.TARGET_ELEMENT_ID,
    )
    assert monitor.previous_content_hash == "new_hash_456"


def test_check_website_no_change(mocker, monitor_with_mock_session):
    monitor = monitor_with_mock_session
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    monitor.previous_content_hash = "same_hash_789"

    mocker.patch.object(monitor, "_fetch_content", return_value="same_html")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._extract_target_content", return_value="same_content")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._calculate_hash", return_value="same_hash_789")

    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call("No change detected in content.", current_hash="same_hash_789")

    change_detected_call_present = False
    for call_args_tuple in mock_logger.info.call_args_list:
        if call_args_tuple.args and "CHANGE DETECTED" in call_args_tuple.args[0]:
            change_detected_call_present = True
            break
    assert not change_detected_call_present
    assert monitor.previous_content_hash == "same_hash_789"


def test_manage_schedule_initial_peak_and_first_check(mocker, monitor_with_mock_session):
    monitor = monitor_with_mock_session
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._get_current_schedule_type", return_value="peak")
    mock_check_changes_method = mocker.patch.object(monitor, "check_website_for_changes")

    assert monitor.previous_content_hash is None

    mock_job_object = MagicMock()
    (
        mock_schedule_lib.every(website_monitor.PEAK_INTERVAL_MIN)
        .to(website_monitor.PEAK_INTERVAL_MAX)
        .seconds.do.return_value
    ) = mock_job_object

    monitor.manage_website_check_schedule()

    mock_schedule_lib.every(website_monitor.PEAK_INTERVAL_MIN).to(
        website_monitor.PEAK_INTERVAL_MAX
    ).seconds.do.assert_called_once_with(monitor.check_website_for_changes)

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

    assert monitor.current_job == mock_job_object
    assert monitor.current_schedule_type == "peak"


def test_manage_schedule_change_to_offpeak(mocker, monitor_with_mock_session):
    monitor = monitor_with_mock_session
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._get_current_schedule_type", return_value="offpeak")
    mock_check_changes_method = mocker.patch.object(monitor, "check_website_for_changes")

    initial_mock_job = MagicMock()
    monitor.current_job = initial_mock_job
    monitor.current_schedule_type = "peak"
    monitor.previous_content_hash = "some_initial_hash"

    new_mock_job_object = MagicMock()
    (
        mock_schedule_lib.every(website_monitor.OFFPEAK_INTERVAL_MIN)
        .to(website_monitor.OFFPEAK_INTERVAL_MAX)
        .seconds.do.return_value
    ) = new_mock_job_object

    monitor.manage_website_check_schedule()

    mock_schedule_lib.cancel_job.assert_called_once_with(initial_mock_job)
    mock_logger.info.assert_any_call("Cancelled previous check schedule.", cancelled_schedule_type="peak")

    mock_schedule_lib.every(website_monitor.OFFPEAK_INTERVAL_MIN).to(
        website_monitor.OFFPEAK_INTERVAL_MAX
    ).seconds.do.assert_called_once_with(monitor.check_website_for_changes)
    mock_logger.info.assert_any_call(
        "Scheduled new website check job.",
        type="offpeak",
        min_interval_sec=website_monitor.OFFPEAK_INTERVAL_MIN,
        max_interval_sec=website_monitor.OFFPEAK_INTERVAL_MAX,
    )

    assert monitor.current_job == new_mock_job_object
    assert monitor.current_schedule_type == "offpeak"
    mock_check_changes_method.assert_not_called()


def test_manage_schedule_no_change_needed(mocker, monitor_with_mock_session):
    monitor = monitor_with_mock_session
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.WebsiteMonitor._get_current_schedule_type", return_value="peak")

    mock_existing_job = MagicMock()
    monitor.current_job = mock_existing_job
    monitor.current_schedule_type = "peak"
    monitor.previous_content_hash = "some_hash"

    monitor.manage_website_check_schedule()

    mock_schedule_lib.cancel_job.assert_not_called()
    mock_schedule_lib.every().to().seconds.do.assert_not_called()

    scheduled_new_job_logged = False
    if mock_logger.info.call_args_list:
        for call_args_tuple in mock_logger.info.call_args_list:
            if call_args_tuple.args and call_args_tuple.args[0] == "Scheduled new website check job.":
                scheduled_new_job_logged = True
                break
    assert not scheduled_new_job_logged

    assert monitor.current_job == mock_existing_job
    assert monitor.current_schedule_type == "peak"


def test_website_monitor_init(mocker):
    mock_create_session = mocker.patch("scraper.website_monitor.WebsiteMonitor._create_session_with_retries")
    mock_session_instance = Mock(spec=requests.Session)
    mock_create_session.return_value = mock_session_instance

    monitor = website_monitor.WebsiteMonitor()

    mock_create_session.assert_called_once()
    assert monitor.session == mock_session_instance
    assert monitor.previous_content_hash is None
    assert monitor.current_job is None
    assert monitor.current_schedule_type is None
