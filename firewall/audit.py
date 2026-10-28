"""Append-only audit log. One JSON line per decision, tagged with its control."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []

    def write(self, **record: Any) -> dict[str, Any]:
        record = {"ts": round(time.time(), 3), **record}
        self.records.append(record)
        if self.path:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        return record
