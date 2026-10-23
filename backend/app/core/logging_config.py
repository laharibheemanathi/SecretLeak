"""Logging configuration.

Deliberately conservative: SecretLeak must never log request bodies, pasted
source code, uploaded file contents, credentials or authorization headers.
Only application-level events (scan started/finished, errors) are logged, and
the exception handler logs a short message plus a request id — never payloads.
"""

from __future__ import annotations

import logging

_CONFIGURED = False


def configure_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # uvicorn's default access log records method/path/status only (no bodies),
    # which is safe. We keep it at INFO and never add body logging.
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
