"""Scanner protocol shared by all detection modules."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Iterable, Protocol

from ..core.index import Finding


@dataclasses.dataclass
class ScanContext:
    root: Path
    max_bytes: int = 8 * 1024 * 1024
    follow_symlinks: bool = False
    excluded_dirs: tuple[str, ...] = (
        ".git", "node_modules", ".venv", "venv", "__pycache__",
        "dist", "build", ".aegis",
    )

    def iter_files(self) -> Iterable[Path]:
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in self.excluded_dirs for part in path.parts):
                continue
            try:
                if path.stat().st_size > self.max_bytes * 16:
                    continue
            except OSError:
                continue
            yield path


class Scanner(Protocol):
    name: str

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:  # pragma: no cover
        ...
