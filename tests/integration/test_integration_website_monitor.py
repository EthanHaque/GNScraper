"""Integration tests for the WebsiteMonitor using a live local HTTP server."""

import socket
import threading
import time
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from scraper import website_monitor


class ServerTestState:
    """Holds the mutable dynamic state for the test HTTP server."""

    def __init__(self, html_content: str, target_element_id: str) -> None:
        self.html_content = html_content
        self.target_element_id = target_element_id


class ControllableHTTPRequestHandler(BaseHTTPRequestHandler):
    """A custom HTTP request handler that serves dynamically controllable HTML content."""

    def do_GET(self) -> None:
        """Handle GET requests by serving the current HTML content from server state."""
        try:
            current_state: ServerTestState = self.server.test_state

            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()

            body = f"""<html><head><title>Test Page</title></head><body><h1>Test Server</h1><div id="{current_state.target_element_id}">{current_state.html_content}</div><p>Some other content</p></body></html>"""

            self.wfile.write(body.encode("utf-8"))
        except AttributeError:
            print("CRITICAL: self.server.test_state not found in ControllableHTTPRequestHandler.")
            self.send_error(500, "Server configuration error: test_state missing.")
        except Exception as e:
            print(f"Error in ControllableHTTPRequestHandler: {e}")
            try:
                self.send_error(500, f"Internal server error: {e}")
            except BrokenPipeError:
                pass
            except Exception as e2:
                print(f"Further error sending 500: {e2}")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: ARG002
        """Suppress HTTP server log messages."""
        return


class _StatefulTestHTTPServer(HTTPServer):
    """Custom HTTPServer to hold test state."""

    def __init__(
        self, server_address: tuple[str, int], RequestHandlerClass: Any, initial_state: ServerTestState
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.test_state: ServerTestState = initial_state


@pytest.fixture(scope="module")
def local_http_server_with_state() -> Generator[tuple[str, int, ServerTestState], None, None]:
    """Pytest fixture to start/stop a local HTTP server with controllable state."""
    host = "localhost"
    port = 0
    httpd = None
    server_thread = None

    initial_target_id = "testProductList"
    server_state = ServerTestState(html_content="", target_element_id=initial_target_id)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, 0))
            port = s.getsockname()[1]

        server_address = (host, port)
        httpd = _StatefulTestHTTPServer(server_address, ControllableHTTPRequestHandler, initial_state=server_state)

        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        time.sleep(0.05)

        print(f"Local HTTP server started on {host}:{port} for module tests...")
        yield f"http://{host}", port, server_state

    finally:
        if httpd:
            print(f"\nShutting down local HTTP server on {host}:{port}...")
            httpd.shutdown()
            httpd.server_close()
        if server_thread:
            server_thread.join(timeout=5)
        print("Local HTTP server shut down.")


@pytest.mark.integration
def test_website_monitor_change_detection_with_local_server(
    mocker,
    local_http_server_with_state: tuple[str, int, ServerTestState],
):
    """
    Integration test for WebsiteMonitor's change detection using a local HTTP server.
    Ensures that actual email sending is mocked out.
    """
    server_host, server_port, server_state = local_http_server_with_state
    local_url = f"{server_host}:{server_port}/testpage"

    mocker.patch("scraper.website_monitor.URL", local_url)
    mocker.patch("scraper.website_monitor.TARGET_ELEMENT_ID", server_state.target_element_id)

    mocker.patch("scraper.website_monitor.EMAIL_NOTIFICATIONS_ENABLED", True)
    mocker.patch("scraper.website_monitor.EMAIL_RECIPIENTS", ["test@example.com"])
    mocker.patch("scraper.website_monitor.SMTP_HOST", "smtp.example.com")
    mocker.patch("scraper.website_monitor.SMTP_USER", "user")
    mocker.patch("scraper.website_monitor.SMTP_PASSWORD", "pass")
    mocker.patch("scraper.website_monitor.EMAIL_SENDER", "sender")

    mock_logger = mocker.patch("scraper.website_monitor.logger")
    monitor = website_monitor.WebsiteMonitor()

    mock_send_email_method = mocker.patch.object(monitor, "_send_email_notification")

    # --- 1. Initial Check ---
    server_state.html_content = "<p>Initial Content V1</p>"
    initial_target_html_as_expected_by_test = (
        f'<div id="{server_state.target_element_id}">{server_state.html_content}</div>'
    )
    initial_expected_hash = monitor._calculate_hash(initial_target_html_as_expected_by_test)

    print(f"\n[Test] Performing initial check. Server content: '{server_state.html_content}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call(
        "Initial content check complete or content re-established.",
        current_hash=initial_expected_hash,
        target_id=server_state.target_element_id,
    )
    assert monitor.previous_content_hash == initial_expected_hash
    mock_send_email_method.assert_not_called()

    change_detected_logged = any(
        call_args_tuple.args and "CHANGE DETECTED" in call_args_tuple.args[0]
        for call_args_tuple in mock_logger.info.call_args_list
    )
    assert not change_detected_logged, "CHANGE DETECTED logged on initial check"

    mock_logger.reset_mock()
    mock_send_email_method.reset_mock()

    # --- 2. Content Change and Detection ---
    server_state.html_content = "<span>Updated Content V2!</span>"
    updated_target_html_as_expected_by_test = (
        f'<div id="{server_state.target_element_id}">{server_state.html_content}</div>'
    )
    updated_expected_hash = monitor._calculate_hash(updated_target_html_as_expected_by_test)

    time.sleep(0.1)

    print(f"[Test] Performing check after content update. Server content: '{server_state.html_content}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call(
        "CHANGE DETECTED: Monitored content has updated.",
        previous_hash=initial_expected_hash,
        new_hash=updated_expected_hash,
        page_url=local_url,
        element_id=server_state.target_element_id,
    )
    assert monitor.previous_content_hash == updated_expected_hash

    mock_send_email_method.assert_called_once()

    mock_logger.reset_mock()
    mock_send_email_method.reset_mock()

    # --- 3. No Change Check ---
    time.sleep(0.1)

    print(f"[Test] Performing check with no content change. Server content: '{server_state.html_content}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call("No change detected in content.", current_hash=updated_expected_hash)
    mock_send_email_method.assert_not_called()

    change_detected_logged_again = any(
        call_args_tuple.args and "CHANGE DETECTED" in call_args_tuple.args[0]
        for call_args_tuple in mock_logger.info.call_args_list
    )
    assert not change_detected_logged_again, "CHANGE DETECTED logged when no change occurred"
    assert monitor.previous_content_hash == updated_expected_hash


@pytest.mark.integration
def test_website_monitor_multiple_elements_detection(
    mocker,
    local_http_server_with_state: tuple[str, int, ServerTestState],
):
    """
    Integration test for WebsiteMonitor's change detection when TARGET_ELEMENT_ID
    refers to multiple elements within a larger container.
    """
    server_host, server_port, server_state = local_http_server_with_state
    local_url = f"{server_host}:{server_port}/testpage"

    MONITORED_ITEM_ID = "productItem"

    mocker.patch("scraper.website_monitor.URL", local_url)
    mocker.patch("scraper.website_monitor.TARGET_ELEMENT_ID", MONITORED_ITEM_ID)

    mocker.patch("scraper.website_monitor.EMAIL_NOTIFICATIONS_ENABLED", True)
    mocker.patch("scraper.website_monitor.EMAIL_RECIPIENTS", ["test@example.com"])
    mocker.patch("scraper.website_monitor.SMTP_HOST", "smtp.example.com")
    mocker.patch("scraper.website_monitor.SMTP_USER", "user")
    mocker.patch("scraper.website_monitor.SMTP_PASSWORD", "pass")
    mocker.patch("scraper.website_monitor.EMAIL_SENDER", "sender")

    mock_logger = mocker.patch("scraper.website_monitor.logger")
    monitor = website_monitor.WebsiteMonitor()
    mock_send_email_method = mocker.patch.object(monitor, "_send_email_notification")

    # --- Phase 1: Initial state with two items ---
    item1_v1 = f'<div id="{MONITORED_ITEM_ID}">Item A Content</div>'
    item2_v1 = f'<div id="{MONITORED_ITEM_ID}">Item B Content</div>'
    server_state.html_content = f"{item1_v1}{item2_v1}<p>Other stuff</p>"

    expected_combined_v1 = "\n".join([item1_v1, item2_v1])
    hash_v1 = monitor._calculate_hash(expected_combined_v1)

    print(f"\n[Test Multiple] Initial check. Server's inner HTML: '{server_state.html_content}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call(
        "Initial content check complete or content re-established.", current_hash=hash_v1, target_id=MONITORED_ITEM_ID
    )
    assert monitor.previous_content_hash == hash_v1
    mock_send_email_method.assert_not_called()
    mock_logger.reset_mock()
    mock_send_email_method.reset_mock()

    # --- Phase 2: Content of one item changes ---
    item1_v2 = f'<div id="{MONITORED_ITEM_ID}">Item A MODIFIED</div>'
    server_state.html_content = f"{item1_v2}{item2_v1}<p>Other stuff</p>"

    expected_combined_v2 = "\n".join([item1_v2, item2_v1])
    hash_v2 = monitor._calculate_hash(expected_combined_v2)
    time.sleep(0.1)

    print(f"[Test Multiple] Check after item content change. Server's inner HTML: '{server_state.html_content}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call(
        "CHANGE DETECTED: Monitored content has updated.",
        previous_hash=hash_v1,
        new_hash=hash_v2,
        page_url=local_url,
        element_id=MONITORED_ITEM_ID,
    )
    assert monitor.previous_content_hash == hash_v2
    mock_send_email_method.assert_called_once()
    mock_logger.reset_mock()
    mock_send_email_method.reset_mock()

    # --- Phase 3: Number of items changes (one item added) ---
    item3_v1 = f'<div id="{MONITORED_ITEM_ID}">Item C New</div>'
    server_state.html_content = f"{item1_v2}{item2_v1}{item3_v1}<p>Other stuff</p>"

    expected_combined_v3 = "\n".join([item1_v2, item2_v1, item3_v1])
    hash_v3 = monitor._calculate_hash(expected_combined_v3)
    time.sleep(0.1)

    print(f"[Test Multiple] Check after adding an item. Server's inner HTML: '{server_state.html_content}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call(
        "CHANGE DETECTED: Monitored content has updated.",
        previous_hash=hash_v2,
        new_hash=hash_v3,
        page_url=local_url,
        element_id=MONITORED_ITEM_ID,
    )
    assert monitor.previous_content_hash == hash_v3
    mock_send_email_method.assert_called_once()
    mock_logger.reset_mock()
    mock_send_email_method.reset_mock()

    # --- Phase 4: No change (with multiple items) ---
    time.sleep(0.1)
    print(f"[Test Multiple] Check with no change. Server's inner HTML: '{server_state.html_content}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call("No change detected in content.", current_hash=hash_v3)
    mock_send_email_method.assert_not_called()
    assert monitor.previous_content_hash == hash_v3
