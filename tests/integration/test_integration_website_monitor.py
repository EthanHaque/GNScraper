"""
Integration tests for the WebsiteMonitor using a live local HTTP server.

NOTE: To run tests marked with '@pytest.mark.integration', ensure the
'integration' marker is registered in your pytest configuration file
(e.g., pyproject.toml or pytest.ini). Example for pyproject.toml:

[tool.pytest.ini_options]
markers = [
    "integration: marks tests as integration tests",
]
"""

import socket
import threading
import time
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from scraper import website_monitor

_SERVER_HTML_CONTENT: str = ""
_TARGET_ELEMENT_ID_FOR_SERVER: str = "testProductList"


class ControllableHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    A custom HTTP request handler that serves dynamically controllable HTML content.
    """

    def do_GET(self) -> None:
        """Handle GET requests by serving the current _SERVER_HTML_CONTENT."""
        try:
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()

            body = f"""<html><head><title>Test Page</title></head><body><h1>Test Server</h1><div id="{_TARGET_ELEMENT_ID_FOR_SERVER}">{_SERVER_HTML_CONTENT}</div><p>Some other content</p></body></html>"""

            self.wfile.write(body.encode("utf-8"))
        except Exception as e:
            print(f"Error in ControllableHTTPRequestHandler: {e}")
            try:
                self.send_error(500, f"Internal server error: {e}")
            except BrokenPipeError:
                pass
            except Exception as e2:
                print(f"Further error sending 500: {e2}")

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress HTTP server log messages."""
        return


@pytest.fixture(scope="module")
def local_http_server() -> Generator[tuple[str, int], None, None]:
    """
    Pytest fixture to start and stop a local HTTP server for integration tests.
    """
    host = "localhost"
    port = 0
    httpd = None
    server_thread = None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, 0))
            port = s.getsockname()[1]

        server_address = (host, port)
        httpd = HTTPServer(server_address, ControllableHTTPRequestHandler)

        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        time.sleep(0.05)

        print(f"Local HTTP server started on {host}:{port} for module tests...")
        yield f"http://{host}", port

    finally:
        if httpd:
            print(f"\nShutting down local HTTP server on {host}:{port}...")
            httpd.shutdown()
            httpd.server_close()
        if server_thread:
            server_thread.join(timeout=5)
        print("Local HTTP server shut down.")


@pytest.mark.integration
def test_website_monitor_change_detection_with_local_server(mocker, local_http_server: tuple[str, int]):
    """
    Integration test for WebsiteMonitor's change detection using a local HTTP server.
    """
    global _SERVER_HTML_CONTENT

    server_host, server_port = local_http_server
    local_url = f"{server_host}:{server_port}/testpage"

    mocker.patch("scraper.website_monitor.URL", local_url)
    mocker.patch("scraper.website_monitor.TARGET_ELEMENT_ID", _TARGET_ELEMENT_ID_FOR_SERVER)

    mock_logger = mocker.patch("scraper.website_monitor.logger")
    monitor = website_monitor.WebsiteMonitor()

    _SERVER_HTML_CONTENT = "<p>Initial Content V1</p>"
    initial_target_html_as_expected_by_test = f'<div id="{_TARGET_ELEMENT_ID_FOR_SERVER}">{_SERVER_HTML_CONTENT}</div>'
    initial_expected_hash = monitor._calculate_hash(initial_target_html_as_expected_by_test)

    print(f"\n[Test] Performing initial check. Server content: '{_SERVER_HTML_CONTENT}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call(
        "Initial content check complete or content re-established.",
        current_hash=initial_expected_hash,
        target_id=_TARGET_ELEMENT_ID_FOR_SERVER,
    )
    assert monitor.previous_content_hash == initial_expected_hash

    change_detected_logged = any(
        call_args_tuple.args and "CHANGE DETECTED" in call_args_tuple.args[0]
        for call_args_tuple in mock_logger.info.call_args_list
    )
    assert not change_detected_logged, "CHANGE DETECTED logged on initial check"

    mock_logger.reset_mock()

    _SERVER_HTML_CONTENT = "<span>Updated Content V2!</span>"
    updated_target_html_as_expected_by_test = f'<div id="{_TARGET_ELEMENT_ID_FOR_SERVER}">{_SERVER_HTML_CONTENT}</div>'
    updated_expected_hash = monitor._calculate_hash(updated_target_html_as_expected_by_test)

    time.sleep(0.1)

    print(f"[Test] Performing check after content update. Server content: '{_SERVER_HTML_CONTENT}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call(
        "CHANGE DETECTED: Monitored content has updated.",
        previous_hash=initial_expected_hash,
        new_hash=updated_expected_hash,
        page_url=local_url,
        element_id=_TARGET_ELEMENT_ID_FOR_SERVER,
    )
    assert monitor.previous_content_hash == updated_expected_hash

    mock_logger.reset_mock()

    time.sleep(0.1)

    print(f"[Test] Performing check with no content change. Server content: '{_SERVER_HTML_CONTENT}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call("No change detected in content.", current_hash=updated_expected_hash)
    change_detected_logged_again = any(
        call_args_tuple.args and "CHANGE DETECTED" in call_args_tuple.args[0]
        for call_args_tuple in mock_logger.info.call_args_list
    )
    assert not change_detected_logged_again, "CHANGE DETECTED logged when no change occurred"
    assert monitor.previous_content_hash == updated_expected_hash
