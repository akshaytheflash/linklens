import json
import logging
import random
import sys
import time
import uuid
from typing import Any, Dict

from flask import g, request


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data: Dict[str, Any] = {
            "ts": round(time.time(), 3),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        # Merge anything a caller passed via extra={...}
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in ("message", "args", "asctime", "created", "msecs", "relativeCreated", "levelno", "levelname", "name", "msg", "exc_info", "exc_text", "stack_info", "fname", "lineno", "funcName", "pathname", "filename", "module", "processName", "process", "threadName", "thread", "taskName"):
                continue
            data[key] = value
        try:
            data["request_id"] = g.request_id
            data["path"] = request.path
            data["ip"] = request.headers.get("X-Forwarded-For", request.remote_addr)
            data["method"] = request.method
        except Exception:
            pass
        return json.dumps(data, ensure_ascii=False)


class SamplingLogger:
    """Wraps the standard logger and drops some info/warning lines so chatty
    environments don't get buried in noise. Errors always pass through."""

    def __init__(self, inner: logging.Logger, rate: float) -> None:
        self.inner = inner
        self.rate = max(0.0, min(1.0, rate))

    def info(self, msg: str, *args, **kwargs):
        if random.random() <= self.rate:
            self.inner.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        if random.random() <= self.rate:
            self.inner.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        self.inner.error(msg, *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs):
        self.inner.exception(msg, *args, **kwargs)


def setup_json_logging(sample_rate: float = 1.0) -> SamplingLogger:
    logger = logging.getLogger("app")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.handlers = [handler]
    logger.propagate = False
    return SamplingLogger(logger, sample_rate)


def assign_request_id():
    g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
