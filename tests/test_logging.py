"""Test the logging stuff"""
from typing import Any
import logging
import datetime
import re
import os

from libpvarki.logging import DEFAULT_LOG_FORMAT, init_logging


def test_log_format() -> None:
    """Check that the default format contains some things we want"""
    assert "pathname" in DEFAULT_LOG_FORMAT
    assert "funcName" in DEFAULT_LOG_FORMAT
    assert "lineno" in DEFAULT_LOG_FORMAT
    assert "asctime" in DEFAULT_LOG_FORMAT


def test_logging_init() -> None:
    """Test that ini_logging does not explode"""
    os.environ["LOG_GLOBAL_LABELS_JSON"] = '{"globaltag": "the value", "another_global_tag": "ditto"}'
    init_logging(logging.DEBUG)
    del os.environ["LOG_GLOBAL_LABELS_JSON"]


# FIXME: what is the correct type for capsys ??
def test_logging(capsys: Any) -> None:
    """Check that we got all level of messages to capsys"""
    init_logging(logging.DEBUG)  # we must explicitly init again due to capsys
    isots_thismin_regex = r"^\[" + re.escape(datetime.datetime.utcnow().isoformat()[:17]) + r"[0-9]{2}\.[0-9]{3}Z\]"
    logging.getLogger(__name__).debug("Test message debug")
    logging.getLogger(__name__).info("Test message info")
    logging.getLogger(__name__).warning("Test message warn")
    logging.getLogger(__name__).error("Test message error")

    # Check that the log lines start as expected
    (_, stderr) = capsys.readouterr()
    assert re.search(isots_thismin_regex + re.escape("[DEBUG]"), stderr, flags=re.MULTILINE)
    assert re.search(isots_thismin_regex + re.escape("[INFO]"), stderr, flags=re.MULTILINE)
    assert re.search(isots_thismin_regex + re.escape("[WARNING]"), stderr, flags=re.MULTILINE)
    assert re.search(isots_thismin_regex + re.escape("[ERROR]"), stderr, flags=re.MULTILINE)
