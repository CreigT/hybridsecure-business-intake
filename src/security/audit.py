"""Structured, secret-minimizing JSONL audit events."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.security.intake_security import redact


class AuditLogger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def write(self, **event: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {"timestamp": datetime.now(UTC).isoformat(), **self._redact_event(event)}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")

    def _redact_event(self, value: Any) -> Any:
        if isinstance(value, str):
            return redact(value)
        if isinstance(value, dict):
            return {key: self._redact_event(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._redact_event(item) for item in value]
        return value
