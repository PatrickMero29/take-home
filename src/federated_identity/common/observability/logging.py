"""Structured, bounded logging without request bodies, credentials, or query strings."""

import json
import logging

from federated_identity.common.settings.runtime import ServiceId

APPLICATION_EVENTS = frozenset(
    {"runtime_started", "startup_failed", "bootstrap_failed", "logout_dispatch_failed"}
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, object] = {
            "level": record.levelname,
            "logger": record.name,
            # Dependency messages/arguments can contain URLs, SQL parameters,
            # passwords or tokens. Emit a fixed event, never interpolate them.
            "event": (
                record.msg
                if record.name.startswith("federated_identity")
                and isinstance(record.msg, str)
                and record.msg in APPLICATION_EVENTS
                else "dependency_event"
            ),
        }
        # The runtime emits only fixed event names and explicitly selected public
        # fields; external exception text and tracebacks are not serialized.
        if record.exc_info and record.exc_info[0]:
            event["error_type"] = record.exc_info[0].__name__
        service = getattr(record, "service", None)
        if isinstance(service, str) and service in {item.value for item in ServiceId}:
            event["service"] = service
        return json.dumps(event, separators=(",", ":"))


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    for namespace in ("authlib", "sqlalchemy", "httpx2", "httpcore2"):
        logging.getLogger(namespace).setLevel(logging.WARNING)
    # Authlib's debug messages contain token dictionaries. Every existing child
    # is constrained even if a parent previously had a more permissive level.
    for name, logger in logging.Logger.manager.loggerDict.items():
        if name.startswith("authlib") and isinstance(logger, logging.Logger):
            logger.setLevel(logging.WARNING)
