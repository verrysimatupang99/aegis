"""Optional YARA-based detector.

Loads .yar/.yara files from a configurable directory and runs them across
project files. Soft-fails (logs and skips) when `yara-python` is not
installed, so the scanner is opt-in via `pip install -e .[yara]`.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from ..core.index import Finding, fingerprint
from .base import ScanContext


class YaraScanner:
    name = "yara"

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir or Path(
            os.environ.get("AEGIS_YARA_DIR", "data/yara")
        )
        self._rules = None
        self._error: str | None = None
        self._compile()

    def _compile(self) -> None:
        try:
            import yara  # type: ignore
        except ImportError:
            self._error = "yara-python not installed"
            return
        if not self.rules_dir.is_dir():
            self._error = f"rules dir missing: {self.rules_dir}"
            return
        files = sorted(
            str(p) for p in self.rules_dir.rglob("*") if p.suffix in (".yar", ".yara")
        )
        if not files:
            self._error = f"no rules found in {self.rules_dir}"
            return
        try:
            self._rules = yara.compile(filepaths={Path(f).stem: f for f in files})
        except Exception as exc:  # noqa: BLE001
            self._error = f"yara compile failed: {exc}"
            self._rules = None

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        if self._rules is None:
            return
        for path in ctx.iter_files():
            try:
                if path.stat().st_size > ctx.max_bytes * 4:
                    continue
                matches = self._rules.match(filepath=str(path), timeout=10)
            except Exception:  # noqa: BLE001
                continue
            for m in matches:
                meta = dict(getattr(m, "meta", {}) or {})
                tags = list(getattr(m, "tags", []) or [])
                severity = str(meta.get("severity", "medium")).lower()
                yield Finding(
                    path=str(path),
                    scanner=self.name,
                    rule=str(m.rule),
                    severity=severity if severity in ("critical", "high", "medium", "low", "info") else "medium",
                    line=None,
                    fingerprint=fingerprint(self.name, str(path), str(m.rule)),
                    details={
                        "tags": tags,
                        "meta": {k: str(v) for k, v in meta.items()},
                        "namespace": getattr(m, "namespace", ""),
                    },
                )
