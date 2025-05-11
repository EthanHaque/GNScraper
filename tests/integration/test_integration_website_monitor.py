"""
Integration tests for the WebsiteMonitor using a live local HTTP server.

These tests verify the core change detection mechanism by:
1. Starting a local HTTP server.
2. Serving initial content.
3. Having the WebsiteMonitor check this content.
4. Modifying the content served by the local server.
5. Having the WebsiteMonitor check again and detect the change.
6. Checking again to ensure no false positive "change" is reported.
"""

import pytest
import threading
import time
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Tuple, Generator, Any

from scraper import website_monitor  # The module we are testing

# --- Globals to control server content for tests ---
# In a more complex scenario, this state might be managed via a class
# or passed differently to the handler, but for focused tests,
# module-level control is straightforward.
_SERVER_HTML_CONTENT: str = ""
_TARGET_ELEMENT_ID_FOR_SERVER: str = "testProductList"


class ControllableHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    A custom HTTP request handler that serves dynamically controllable HTML content.
    It uses the global _SERVER_HTML_CONTENT and _TARGET_ELEMENT_ID_FOR_SERVER.
    """

    def do_GET(self) -> None:
        """Handle GET requests by serving the current _SERVER_HTML_CONTENT."""
        try:
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            # Construct HTML with the target element and current content
            body = f"""
            <html>
                <head><title>Test Page</title></head>
                <body>
                    <h1>Test Server</h1>
                    <div id="{_TARGET_ELEMENT_ID_FOR_SERVER}">
                        {_SERVER_HTML_CONTENT}
                    </div>
                    <p>Some other content</p>
                </body>
            </html>
            """
            self.wfile.write(body.encode("utf-8"))
        except Exception as e:
            # If an error occurs within the handler, try to send a 500 response
            # This helps in debugging server-side issues during tests.
            print(f"Error in ControllableHTTPRequestHandler: {e}")  # Print to stderr for visibility
            try:
                self.send_error(500, f"Internal server error: {e}")
            except BrokenPipeError:  # Client might have disconnected
                pass
            except Exception as e2:  # Fallback if send_error also fails
                print(f"Further error sending 500: {e2}")

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress HTTP server log messages to keep test output clean."""
        return


@pytest.fixture(scope="module")
def local_http_server() -> Generator[Tuple[str, int], None, None]:
    """
    Pytest fixture to start and stop a local HTTP server for integration tests.

    The server runs in a separate thread and serves content defined by
    the global _SERVER_HTML_CONTENT.

    Yields
    ------
    Tuple[str, int]
        A tuple containing the base URL (e.g., "http://localhost") and port
        of the running local server.
    """
    host = "localhost"
    # Find an available port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))  # Bind to port 0 to let the OS choose an available port
        port = s.getsockname()[1]

    server_address = (host, port)
    httpd = HTTPServer(server_address, ControllableHTTPRequestHandler)

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    print(f"Local HTTP server started on {host}:{port} for module tests...")

    yield f"http://{host}", port

    print(f"\nShutting down local HTTP server on {host}:{port}...")
    httpd.shutdown()
    httpd.server_close()  # Ensure the socket is closed
    server_thread.join(timeout=5)  # Wait for the server thread to finish
    print("Local HTTP server shut down.")


@pytest.mark.integration
def test_website_monitor_change_detection_with_local_server(mocker, local_http_server: Tuple[str, int]):
    """
    Integration test for WebsiteMonitor's change detection using a local HTTP server.

    Steps:
    1. Sets initial content on the local server.
    2. Monitor performs an initial check.
    3. Verifies no "change detected" log and hash is stored.
    4. Updates content on the local server.
    5. Monitor performs another check.
    6. Verifies "change detected" log and hash is updated.
    7. Monitor performs a final check with no content change.
    8. Verifies no "change detected" log and hash remains the same.
    """
    global _SERVER_HTML_CONTENT  # Allow modification of the server's content

    server_host, server_port = local_http_server
    local_url = f"{server_host}:{server_port}/testpage"

    # Patch the constants in the website_monitor module for this test
    mocker.patch("scraper.website_monitor.URL", local_url)
    mocker.patch("scraper.website_monitor.TARGET_ELEMENT_ID", _TARGET_ELEMENT_ID_FOR_SERVER)

    # Mock the logger to inspect its calls
    mock_logger = mocker.patch("scraper.website_monitor.logger")

    # We don't want the scheduler to run in this integration test,
    # so we won't call monitor.run() or monitor.manage_website_check_schedule()
    # directly. We will instantiate the monitor and call its check method.
    monitor = website_monitor.WebsiteMonitor()

    # --- 1. Initial Check ---
    _SERVER_HTML_CONTENT = "<p>Initial Content V1</p>"
    initial_expected_hash = monitor._calculate_hash(
        f'<div id="{_TARGET_ELEMENT_ID_FOR_SERVER}">{_SERVER_HTML_CONTENT}</div>'
    )

    print(f"\n[Test] Performing initial check. Server content: '{_SERVER_HTML_CONTENT}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call(
        "Initial content check complete or content re-established.",
        current_hash=initial_expected_hash,
        target_id=_TARGET_ELEMENT_ID_FOR_SERVER,
    )
    assert monitor.previous_content_hash == initial_expected_hash
    # Ensure "CHANGE DETECTED" was not logged yet
    for call_args_tuple in mock_logger.info.call_args_list:
        if call_args_tuple.args and "CHANGE DETECTED" in call_args_tuple.args[0]:
            pytest.fail("CHANGE DETECTED logged on initial check")

    mock_logger.reset_mock()  # Reset for the next phase

    # --- 2. Content Change and Detection ---
    _SERVER_HTML_CONTENT = "<span>Updated Content V2!</span>"
    updated_expected_hash = monitor._calculate_hash(
        f'<div id="{_TARGET_ELEMENT_ID_FOR_SERVER}">{_SERVER_HTML_CONTENT}</div>'
    )

    # Add a small delay to ensure the server has processed any previous request
    # and is ready for a new one, though with direct calls it's less critical.
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

    # --- 3. No Change Check ---
    # _SERVER_HTML_CONTENT remains "<span>Updated Content V2!</span>"
    time.sleep(0.1)

    print(f"[Test] Performing check with no content change. Server content: '{_SERVER_HTML_CONTENT}'")
    monitor.check_website_for_changes()

    mock_logger.info.assert_any_call("No change detected in content.", current_hash=updated_expected_hash)
    # Ensure "CHANGE DETECTED" was NOT logged for this check
    for call_args_tuple in mock_logger.info.call_args_list:
        if call_args_tuple.args and "CHANGE DETECTED" in call_args_tuple.args[0]:
            pytest.fail("CHANGE DETECTED logged when no change occurred")
    assert monitor.previous_content_hash == updated_expected_hash  # Hash remains the same
