# tests/unit/test_website_monitor_core.py
"""
unit tests for the core functionalities of the websitemonitor class.

this suite tests session creation, content fetching, parsing, hashing,
scheduling logic, and the main change detection workflow, excluding
direct tests of notification sending mechanisms (which are in a separate file).
"""

import datetime
import hashlib
from unittest.mock import magicmock, mock, any

import pytest
import requests  # for requests.exceptions and using the original session for spec
import schedule  # for schedule.clear()

# import the module from your package
from scraper import website_monitor


@pytest.fixture(autouse=true)
def clear_schedule_before_each_test():
    """ensures the schedule is clear before and after each test."""
    schedule.clear()
    yield
    schedule.clear()


@pytest.fixture
def mock_session(mocker):
    """fixture to provide a mocked requests.session instance."""
    session = mock(spec=requests.session)  # use original requests.session for spec
    session.headers = {}  # mock the headers attribute as it's updated
    session.mount = mock()
    return session


@pytest.fixture
def monitor_instance(mocker, mock_session) -> website_monitor.websitemonitor:
    """
    provides a websitemonitor instance with its _create_session_with_retries
    method patched to return a predefined mock session.
    this means monitor.session will be the mock_session.
    """
    # patch the static method on the class
    mocker.patch("scraper.website_monitor.websitemonitor._create_session_with_retries", return_value=mock_session)
    monitor = website_monitor.websitemonitor()
    return monitor


# --- tests for static/helper methods ---


def test_create_session_with_retries(mocker):
    """test the static _create_session_with_retries method."""
    # patch external dependencies used by _create_session_with_retries
    # this mock_requests_session_cls is what website_monitor._create_session_with_retries will see and use
    mock_requests_session_cls_in_module = mocker.patch("scraper.website_monitor.requests.session")
    mock_http_adapter_cls = mocker.patch("scraper.website_monitor.httpadapter")
    mock_retry_cls = mocker.patch("scraper.website_monitor.retry")

    # this mock_session_instance is the one we expect _create_session_with_retries to return
    # after it calls the (mocked) scraper.website_monitor.requests.session()
    expected_returned_session_instance = mock(spec=requests.sessions.session)  # use original requests.session for spec
    expected_returned_session_instance.headers = mock()  # ensure headers attribute exists
    mock_requests_session_cls_in_module.return_value = expected_returned_session_instance

    # call the method under test
    actual_session = website_monitor.websitemonitor._create_session_with_retries()

    assert actual_session == expected_returned_session_instance
    mock_requests_session_cls_in_module.assert_called_once()  # check that the patched session constructor was called
    mock_retry_cls.assert_called_once_with(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["head", "get", "options"],
    )
    mock_http_adapter_cls.assert_called_once_with(max_retries=mock_retry_cls.return_value)
    # assert calls on the session instance that was returned by the mocked session constructor
    expected_returned_session_instance.mount.assert_any_call("http://", mock_http_adapter_cls.return_value)
    expected_returned_session_instance.mount.assert_any_call("https://", mock_http_adapter_cls.return_value)
    expected_returned_session_instance.headers.update.assert_called_once_with(
        {"user-agent": website_monitor.user_agent}
    )


def test_extract_target_content_found(mocker):
    """tests _extract_target_content when the element is found."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    html = (
        f"<html><body><div id='{website_monitor.target_element_id}'>expected text <p>more</p></div>extra</body></html>"
    )
    expected_str = f'<div id="{website_monitor.target_element_id}">expected text <p>more</p></div>'

    # call as a static method
    content = website_monitor.websitemonitor._extract_target_content(html, website_monitor.target_element_id)

    assert content == expected_str
    mock_logger.debug.assert_any_call("target element found.", target_id=website_monitor.target_element_id)


def test_extract_target_content_not_found(mocker):
    """tests _extract_target_content when the element is not found."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    html = "<html><body><div>nothing here</div></body></html>"

    content = website_monitor.websitemonitor._extract_target_content(html, website_monitor.target_element_id)

    assert content is none
    mock_logger.warning.assert_called_once_with(
        "target element not found in html content.",
        target_id=website_monitor.target_element_id,
        page_url=website_monitor.url,  # url is a module constant
    )


def test_extract_target_content_empty_or_invalid_html(mocker):
    """tests _extract_target_content with none or malformed html."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    # test 1: none input
    assert website_monitor.websitemonitor._extract_target_content(none, website_monitor.target_element_id) is none
    mock_logger.debug.assert_any_call("html content is none, cannot extract target content.")
    mock_logger.warning.assert_not_called()  # no warning for none input
    mock_logger.error.assert_not_called()  # no error for none input
    mock_logger.reset_mock()  # reset for the next part of the test

    # test 2: malformed html (beautifulsoup is lenient, might lead to "not found")
    malformed_html = "<html><body><div id='productlist'"  # incomplete attribute
    content = website_monitor.websitemonitor._extract_target_content(malformed_html, website_monitor.target_element_id)
    assert content is none
    # expect a warning because the element (due to malformed id) won't be found
    mock_logger.warning.assert_called_once_with(
        "target element not found in html content.",
        target_id=website_monitor.target_element_id,
        page_url=website_monitor.url,
    )
    mock_logger.error.assert_not_called()  # beautifulsoup usually doesn't error on this


def test_calculate_hash():
    """tests the static _calculate_hash method."""
    content1 = "hello world"
    hash1 = website_monitor.websitemonitor._calculate_hash(content1)

    assert hash1 == hashlib.sha256(content1.encode("utf-8")).hexdigest()
    assert website_monitor.websitemonitor._calculate_hash(content1) == hash1  # consistency
    assert website_monitor.websitemonitor._calculate_hash("other content") != hash1
    assert website_monitor.websitemonitor._calculate_hash(none) == "element_not_found_or_empty"


@pytest.mark.parametrize(
    "current_time_tuple, expected_type",
    [
        ((10, 0, 0), "peak"),
        ((3, 0, 0), "offpeak"),
        ((22, 0, 0), "offpeak"),
        ((website_monitor.peak_start_hour, 0, 0), "peak"),
        ((website_monitor.peak_end_hour, 0, 0), "offpeak"),  # at 21:00, it's off-peak
        ((website_monitor.peak_end_hour - 1, 59, 59), "peak"),  # just before off-peak
    ],
)
def test_get_current_schedule_type_parametrized(mocker, current_time_tuple, expected_type):
    """tests the static _get_current_schedule_type method with various times."""
    # patch datetime.datetime where it's used inside scraper.website_monitor
    mock_dt_datetime = mocker.patch("scraper.website_monitor.datetime.datetime")
    mock_dt_datetime.now.return_value.time.return_value = datetime.time(*current_time_tuple)

    assert website_monitor.websitemonitor._get_current_schedule_type() == expected_type


# --- tests for instance methods (using monitor_instance fixture) ---


def test_fetch_content_success_on_instance(mocker, monitor_instance: website_monitor.websitemonitor):
    """tests _fetch_content success using a monitor instance."""
    # monitor_instance.session is already the mock_session from the fixture
    mock_logger = mocker.patch("scraper.website_monitor.logger")  # module logger

    mock_response = mock(spec=requests.response)  # use spec for better response mocking
    mock_response.text = "<html>test content</html>"
    mock_response.status_code = 200  # needed for raise_for_status
    mock_response.raise_for_status = mock()  # mock this method

    monitor_instance.session.get.return_value = mock_response

    html = monitor_instance._fetch_content(website_monitor.url)

    assert html == "<html>test content</html>"
    monitor_instance.session.get.assert_called_once_with(website_monitor.url, timeout=website_monitor.request_timeout)
    mock_response.raise_for_status.assert_called_once()
    mock_logger.error.assert_not_called()


def test_fetch_content_http_error_on_instance(mocker, monitor_instance: website_monitor.websitemonitor):
    """tests _fetch_content with an http error using a monitor instance."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    http_error_instance = requests.exceptions.httperror("test http error")

    # configure the mock response to raise an error when raise_for_status is called
    mock_response = mock(spec=requests.response)
    mock_response.raise_for_status.side_effect = http_error_instance
    monitor_instance.session.get.return_value = mock_response

    html = monitor_instance._fetch_content(website_monitor.url)
    assert html is none
    mock_logger.error.assert_called_once_with(
        "failed to fetch url content.",
        page_url=website_monitor.url,
        error_message=str(http_error_instance),  # error message comes from the exception
        exc_info=false,
    )


def test_check_website_initial_run(mocker, monitor_instance: website_monitor.websitemonitor):
    """tests the first run of check_website_for_changes."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    # mock helper methods called by check_website_for_changes
    mocker.patch.object(monitor_instance, "_fetch_content", return_value="dummy_html_content")
    # _extract_target_content and _calculate_hash are static, so patch them on the class
    mocker.patch(
        "scraper.website_monitor.websitemonitor._extract_target_content", return_value="dummy_extracted_content"
    )
    mocker.patch("scraper.website_monitor.websitemonitor._calculate_hash", return_value="new_hash_123")

    assert monitor_instance.previous_content_hash is none  # initial state
    monitor_instance.check_website_for_changes()

    monitor_instance._fetch_content.assert_called_once_with(website_monitor.url)
    website_monitor.websitemonitor._extract_target_content.assert_called_once_with(
        "dummy_html_content", website_monitor.target_element_id
    )
    website_monitor.websitemonitor._calculate_hash.assert_called_once_with("dummy_extracted_content")

    mock_logger.info.assert_any_call(
        "initial content check complete or content re-established.",
        current_hash="new_hash_123",
        target_id=website_monitor.target_element_id,
    )
    assert monitor_instance.previous_content_hash == "new_hash_123"


def test_check_website_change_detected(mocker, monitor_instance: website_monitor.websitemonitor):
    """tests change detection in check_website_for_changes."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    # mock the notification method to prevent actual notifications and allow assertion
    mock_notify_method = mocker.patch.object(monitor_instance, "_notify_content_change")

    monitor_instance.previous_content_hash = "old_hash_000"  # set prior state

    mocker.patch.object(monitor_instance, "_fetch_content", return_value="new_html")
    mocker.patch("scraper.website_monitor.websitemonitor._extract_target_content", return_value="new_content")
    mocker.patch("scraper.website_monitor.websitemonitor._calculate_hash", return_value="new_hash_456")

    monitor_instance.check_website_for_changes()

    # _notify_content_change should have been called
    mock_notify_method.assert_called_once_with(new_hash="new_hash_456", old_hash="old_hash_000")
    assert monitor_instance.previous_content_hash == "new_hash_456"


def test_check_website_no_change(mocker, monitor_instance: website_monitor.websitemonitor):
    """tests behavior of check_website_for_changes when no change occurs."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_notify_method = mocker.patch.object(monitor_instance, "_notify_content_change")

    monitor_instance.previous_content_hash = "same_hash_789"

    mocker.patch.object(monitor_instance, "_fetch_content", return_value="same_html")
    mocker.patch("scraper.website_monitor.websitemonitor._extract_target_content", return_value="same_content")
    mocker.patch("scraper.website_monitor.websitemonitor._calculate_hash", return_value="same_hash_789")

    monitor_instance.check_website_for_changes()

    mock_logger.info.assert_any_call("no change detected in content.", current_hash="same_hash_789")
    mock_notify_method.assert_not_called()  # ensure notifications were not triggered
    assert monitor_instance.previous_content_hash == "same_hash_789"


def test_manage_schedule_initial_peak_and_first_check(mocker, monitor_instance: website_monitor.websitemonitor):
    """tests initial schedule setup during peak hours and the immediate first check."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    # _get_current_schedule_type is static
    mocker.patch("scraper.website_monitor.websitemonitor._get_current_schedule_type", return_value="peak")
    # mock the method that would be called by the scheduler and potentially by manage_schedule itself
    mock_check_changes_method = mocker.patch.object(monitor_instance, "check_website_for_changes")

    assert monitor_instance.previous_content_hash is none  # key for triggering initial check

    mock_job_object = magicmock()
    # configure the mock for the chained calls of schedule.every()...
    (
        mock_schedule_lib.every(website_monitor.peak_interval_min)
        .to(website_monitor.peak_interval_max)
        .seconds.do.return_value
    ) = mock_job_object

    monitor_instance.manage_website_check_schedule()

    # verify the correct schedule was set
    mock_schedule_lib.every(website_monitor.peak_interval_min).to(
        website_monitor.peak_interval_max
    ).seconds.do.assert_called_once_with(monitor_instance.check_website_for_changes)

    mock_logger.info.assert_any_call(
        "scheduled new website check job.",
        type="peak",
        min_interval_sec=website_monitor.peak_interval_min,
        max_interval_sec=website_monitor.peak_interval_max,
    )
    mock_logger.info.assert_any_call(
        "performing initial website check immediately after (re)scheduling as no baseline hash exists."
    )
    mock_check_changes_method.assert_called_once()  # assert the direct call

    assert monitor_instance.current_job == mock_job_object
    assert monitor_instance.current_schedule_type == "peak"


def test_manage_schedule_change_to_offpeak(mocker, monitor_instance: website_monitor.websitemonitor):
    """tests schedule transition from peak to off-peak."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.websitemonitor._get_current_schedule_type", return_value="offpeak")
    mock_check_changes_method = mocker.patch.object(monitor_instance, "check_website_for_changes")

    # setup initial state as if a peak job was running
    initial_mock_job = magicmock()
    monitor_instance.current_job = initial_mock_job
    monitor_instance.current_schedule_type = "peak"
    monitor_instance.previous_content_hash = "some_initial_hash"  # indicate not the very first run

    new_mock_job_object = magicmock()
    (
        mock_schedule_lib.every(website_monitor.offpeak_interval_min)
        .to(website_monitor.offpeak_interval_max)
        .seconds.do.return_value
    ) = new_mock_job_object

    monitor_instance.manage_website_check_schedule()

    mock_schedule_lib.cancel_job.assert_called_once_with(initial_mock_job)
    mock_logger.info.assert_any_call("cancelled previous check schedule.", cancelled_schedule_type="peak")

    mock_schedule_lib.every(website_monitor.offpeak_interval_min).to(
        website_monitor.offpeak_interval_max
    ).seconds.do.assert_called_once_with(monitor_instance.check_website_for_changes)
    mock_logger.info.assert_any_call(
        "scheduled new website check job.",
        type="offpeak",
        min_interval_sec=website_monitor.offpeak_interval_min,
        max_interval_sec=website_monitor.offpeak_interval_max,
    )

    assert monitor_instance.current_job == new_mock_job_object
    assert monitor_instance.current_schedule_type == "offpeak"
    mock_check_changes_method.assert_not_called()  # not called if previous_content_hash exists


def test_manage_schedule_no_change_needed(mocker, monitor_instance: website_monitor.websitemonitor):
    """tests manage_schedule when no change in schedule type is required."""
    mock_logger = mocker.patch("scraper.website_monitor.logger")
    mock_schedule_lib = mocker.patch("scraper.website_monitor.schedule")
    mocker.patch("scraper.website_monitor.websitemonitor._get_current_schedule_type", return_value="peak")

    # setup as if a peak job is already correctly scheduled
    mock_existing_job = magicmock()
    monitor_instance.current_job = mock_existing_job
    monitor_instance.current_schedule_type = "peak"
    monitor_instance.previous_content_hash = "some_hash"  # not first run

    monitor_instance.manage_website_check_schedule()

    mock_schedule_lib.cancel_job.assert_not_called()
    # ensure no new job scheduling calls like every().to()... were made
    mock_schedule_lib.every().to().seconds.do.assert_not_called()

    scheduled_new_job_logged = false
    if mock_logger.info.call_args_list:  # check if any info logs were made
        for call_args_tuple in mock_logger.info.call_args_list:
            # access positional arguments via .args
            if call_args_tuple.args and call_args_tuple.args[0] == "scheduled new website check job.":
                scheduled_new_job_logged = true
                break
    assert not scheduled_new_job_logged

    assert monitor_instance.current_job == mock_existing_job  # job remains the same
    assert monitor_instance.current_schedule_type == "peak"  # schedule type remains


def test_website_monitor_init(mocker):
    """tests the __init__ method of websitemonitor."""
    # patch the static method _create_session_with_retries called by __init__
    mock_create_session = mocker.patch("scraper.website_monitor.websitemonitor._create_session_with_retries")
    # for the spec of the returned session instance, use the original requests.session
    mock_session_instance = mock(spec=requests.session)
    mock_create_session.return_value = mock_session_instance

    monitor = website_monitor.websitemonitor()

    mock_create_session.assert_called_once()
    assert monitor.session == mock_session_instance
    assert monitor.previous_content_hash is none
    assert monitor.current_job is none
    assert monitor.current_schedule_type is none
    # optionally, assert that the init debug log was made
    # mocker.patch('scraper.website_monitor.logger').debug.assert_called_with("websitemonitor instance initialized.")
