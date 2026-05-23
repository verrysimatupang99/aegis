"""Glasswing journal: append-only, redacted, replayable record of agent actions.

Inspired by Project Glasswing's emphasis on transparency and shareable defensive
artifacts. Every tool invocation, decision, and rule check writes one JSON line
to a rotating file. The journal is the source of truth for audits.
"""

from __future__ import annotations

import dataclasses
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Iterable


_HOME = str(Path.home())


def _redact_value(v: Any) -> Any:
    if isinstance(v, str):
        if _HOME and _HOME in v:
            v = v.replace(_HOME, "~")
        return v
    if isinstance(v, dict):
        return {k: _redact_value(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_redact_value(x) for x in v]
    return v


@dataclasses.dataclass
class Journal:
    root: Path
    rotate_bytes: int = 16 * 1024 * 1024
    session_id: str = dataclasses.field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def _current_path(self) -> Path:
        day = time.strftime("%Y%m%d")
        base = self.root / f"journal-{day}.jsonl"
        if base.exists() and base.stat().st_size >= self.rotate_bytes:
            stamp = time.strftime("%Y%m%dT%H%M%S")
            base.rename(self.root / f"journal-{stamp}.jsonl")
        return base

    def write(self, kind: str, payload: dict[str, Any]) -> str:
        entry_id = uuid.uuid4().hex[:16]
        record = {
            "id": entry_id,
            "ts": time.time(),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z") or time.strftime("%Y-%m-%dT%H:%M:%S"),
            "session": self.session_id,
            "pid": os.getpid(),
            "kind": kind,
            "payload": _redact_value(payload),
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        path = self._current_path()
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return entry_id

    def replay(self, kinds: Iterable[str] | None = None) -> Iterable[dict[str, Any]]:
        wanted = set(kinds) if kinds else None
        for path in sorted(self.root.glob("journal-*.jsonl")):
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if wanted and rec.get("kind") not in wanted:
                        continue
                    yield rec
