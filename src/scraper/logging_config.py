"""
Logging setup for data analysis tasks using structlog for rich console output.

Environment variables
---------------------
LOG_LEVEL      Root logging level (e.g., DEBUG, INFO, WARNING). Default: INFO.
"""

import logging
import logging.config
import os
import sys

import structlog
from structlog.types import Processor


def _get_shared_processors() -> list[Processor]:
    """Return structlog processors useful for data analysis."""
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]


def _configure_stdlib_logging(log_level: str) -> None:
    """
    Configure the standard library logging using dictConfig.

    Sets up a handler to output logs to stdout using structlog's formatter,
    which utilizes ConsoleRenderer for nice console output.

    Parameters
    ----------
    log_level : str
        The minimum log level (e.g., 'INFO', 'DEBUG') for the root logger.
    """
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processor": structlog.dev.ConsoleRenderer(colors=True),
                "foreign_pre_chain": _get_shared_processors(),
            },
        },
        "handlers": {
            "stdout": {
                "class": "logging.StreamHandler",
                "stream": sys.stdout,
                "formatter": "console",
            },
        },
        "root": {
            "handlers": ["stdout"],
            "level": log_level.upper(),
        },
    }
    logging.config.dictConfig(logging_config)


def setup_logging(level: str | None = None) -> None:
    """
    Configure logging and structlog for console output.

    Call this function once at the start of your application or script.
    It sets up both the standard library logging and structlog processors.

    Parameters
    ----------
    level : Optional[str], optional
        The desired minimum log level (e.g., 'DEBUG', 'INFO').
        Overrides the LOG_LEVEL environment variable if provided.
        Defaults to 'INFO' if neither is set.
    """
    log_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()

    _configure_stdlib_logging(log_level=log_level)

    structlog.configure(
        processors=[
            *_get_shared_processors(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Get a structlog logger instance, integrated with standard library logging.

    Parameters
    ----------
    name : Optional[str], optional
        The name for the logger. Typically `__name__` for modules, or a
        descriptive name for specific components or scripts.
        Defaults to None, which usually results in the root logger.

    Returns
    -------
    structlog.stdlib.BoundLogger
        A configured logger instance ready for use.
    """
    return structlog.get_logger(name)


if __name__ == "__main__":
    setup_logging(level="DEBUG")
    log = get_logger(__name__)

    log.debug("Starting script execution.", script_path=__file__)
    log.info("This is an info message.", key="value", number=1000)
    log.warning("Found potential issue.", warning=5)
    try:
        result = 10 / 0
    except ZeroDivisionError:
        log.error("Calculation failed!", input=10, divisor=0, exc_info=True)

    log.info("Processing file A")
    structlog.contextvars.bind_contextvars(filename="file_a.txt")
    log.info("Reading data")
    structlog.contextvars.clear_contextvars()
    log.info("Context cleared")
