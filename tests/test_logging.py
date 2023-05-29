"""Test the logging stuff"""
from typing import Any
import logging
import datetime
import json

from libpvarki.logging import DEFAULT_LOG_FORMAT, init_logging


def test_log_format() -> None:
    """Check that the default format contains some things we want"""
    assert "pathname" in DEFAULT_LOG_FORMAT
    assert "funcName" in DEFAULT_LOG_FORMAT
    assert "lineno" in DEFAULT_LOG_FORMAT
    assert "asctime" in DEFAULT_LOG_FORMAT


# FIXME: What is the correct type hint for monkeypatch ??
def test_logging_init(monkeypatch: Any) -> None:
    """Test that ini_logging does not explode"""
    monkeypatch.setenv("LOG_GLOBAL_LABELS_JSON", '{"globaltag": "the value", "another_global_tag": "ditto"}')
    init_logging(logging.DEBUG)


# FIXME: What is the correct type hint for monkeypatch ??
# FIXME: what is the correct type for capsys ??
def test_logging(capsys: Any, monkeypatch: Any) -> None:
    """Check that we got all level of messages to capsys"""
    monkeypatch.setenv("LOG_GLOBAL_LABELS_JSON", '{"hierarchical.tag.value": "get", "another_global_tag": "ditto"}')
    now = datetime.datetime.now(datetime.timezone.utc)
    init_logging(logging.DEBUG)  # we must explicitly init again due to capsys and ENV mock
    logging.getLogger(__name__).debug("Test message debug")
    logging.getLogger(__name__).info("Test message info")
    logging.getLogger(__name__).warning("Test message warn")
    logging.getLogger(__name__).error("Test message error")

    # Check that the log lines start as expected
    (_, stderr) = capsys.readouterr()
    for line, level in zip(stderr.splitlines(), ("debug", "info", "warning", "error")):
        parsed = json.loads(line)
        assert parsed["log.level"] == level
        msgtime = datetime.datetime.fromisoformat(parsed["@timestamp"].replace("Z", "+00:00"))
        assert msgtime - now < datetime.timedelta(seconds=5)
