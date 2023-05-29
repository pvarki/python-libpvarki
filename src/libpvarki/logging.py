"""Things common for all handlers"""
from typing import Optional, Mapping, Any, Dict, cast
import os
import json
import logging
import logging.config
import time
import datetime
import copy


import ecs_logging


class UTCISOFormatter(logging.Formatter):
    """Output timestamps in UTC ISO timestamps"""

    converter = time.gmtime

    def formatTime(self, record: logging.LogRecord, datefmt: Optional[str] = None) -> str:
        converted = datetime.datetime.fromtimestamp(record.created, tz=datetime.timezone.utc)
        if datefmt:
            formatted = converted.strftime(datefmt)
        else:
            formatted = converted.isoformat(timespec="milliseconds")
        return formatted.replace("+00:00", "Z")


DEFAULT_LOG_FORMAT = (
    "[%(asctime)s][%(levelname)s] %(name)s (%(process)d) %(pathname)s:%(funcName)s:%(lineno)d | %(message)s"
)
DEFAULT_LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "ecs": {
            "()": ecs_logging.StdlibFormatter,
        },
        "utc": {
            "()": UTCISOFormatter,
            "format": DEFAULT_LOG_FORMAT,
        },
        "local": {
            "format": DEFAULT_LOG_FORMAT,
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "ecs",
        },
    },
    "root": {
        "handlers": ["console"],
    },
}

DEFAULT_RECORD_DIR = set(
    list(dir(logging.LogRecord("dummy", 10, "dummy.py", 228, "Dummy", None, None, "dummy", None)))
    + ["message", "asctime"]
)


class AddExtrasFilter(logging.Filter):  # pylint: disable=R0903
    """Add the extra properties and values given at init"""

    def __init__(self, extras: Mapping[str, Any], name: str = "") -> None:
        """init"""
        if not extras or not isinstance(extras, Mapping):
            raise ValueError("extras must be non-empty mapping")
        self.add_extras = extras
        super().__init__(name)

    def filter(self, record: logging.LogRecord) -> bool:
        """Add the extras then call parent filter"""
        for key in self.add_extras:
            setattr(record, key, self.add_extras[key])
        return super().filter(record)


def init_logging(level: int = logging.INFO) -> None:
    """Initialize logging, call this if you don't know any better logging arrangements"""
    labels_json = os.environ.get("LOG_GLOBAL_LABELS_JSON")
    config = cast(Dict[str, Any], copy.deepcopy(DEFAULT_LOGGING_CONFIG))
    # If we have the labels env set, apply filter that sets these labels to all log records
    if labels_json:
        config["filters"] = {
            "global_labels": {
                "()": AddExtrasFilter,
                "extras": json.loads(labels_json),
            },
        }
        for key in config["handlers"]:
            if "filters" not in config["handlers"][key]:
                config["handlers"][key]["filters"] = []
            config["handlers"][key]["filters"].append("global_labels")
    # Set root loglevel to desired
    config["root"]["level"] = level
    logging.config.dictConfig(config)
