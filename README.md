# Gamers Nexus Garage Sale Monitor

Monitors the Gamers Nexus Garage Sale webpage for product listing updates and can send email notifications upon detecting changes.

## Setup

1.  **Prerequisites**:
    * Python 3.12+
    * `pip`
    * SMTP server access (for email notifications)

2.  **Installation**:
    * Clone or download the source.
    * Create and activate a virtual environment:
        ```bash
        python -m venv venv
        source venv/bin/activate
        ```
    * Install dependencies:
        ```bash
        pip install .
        ```

## Configuration (Email Notifications)

Set the following environment variables (e.g., in a `.env` file or your shell):

```env
EMAIL_NOTIFICATIONS_ENABLED="true"
SMTP_HOST="your_smtp_host"                 # e.g., smtp.gmail.com
SMTP_PORT="587"                            # e.g., 587 for TLS
SMTP_USE_TLS="true"
SMTP_USER="your_email_address"
SMTP_PASSWORD="your_email_password_or_app_password"
EMAIL_SENDER="your_sending_email_address"
EMAIL_RECIPIENTS="your_recipient_email_address"
```
*Note: For Gmail with 2FA, use an App Password for `SMTP_PASSWORD`.*

## Running the Monitor

1.  Activate virtual environment.
2.  Ensure environment variables are set.
3.  Run from project root:
    ```bash
    python -m scraper.website_monitor
    ```

## Running Tests

1.  Install test dependencies:
    ```bash
    pip install .[test]
    ```
2.  Run all basic tests:
    ```bash
    pytest
