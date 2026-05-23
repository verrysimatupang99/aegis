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
        # heavy build/cache trees encountered when scanning
        # whole-workspace roots like ~/Documents/Coding
        "target", ".next", ".nuxt", ".turbo", ".parcel-cache",
        "vendor", "coverage", ".cache", ".gradle", ".idea",
        ".pytest_cache", ".mypy_cache", ".ruff_cache",
        "site-packages",
        # large generated/binary content roots
        "gen", "artifacts", "models",
    )

    def iter_files(self) -> Iterable[Path]:
        """Yield files under ``root``, pruning excluded dirs *before* descent.

        Using :func:`os.walk` with in-place ``dirs`` mutation lets us avoid
        recursing into 10+ GB caches like ``target/``, ``node_modules/``,
        ``models/`` entirely. Previously :py:meth:`Path.rglob` would still
        descend, which made whole-workspace scans take many minutes.
        """
        import os

        excluded = set(self.excluded_dirs)
        cap = self.max_bytes * 16
        for dirpath, dirnames, filenames in os.walk(
            self.root, followlinks=self.follow_symlinks
        ):
            # Prune: drop any subdir whose basename is excluded BEFORE descent.
            dirnames[:] = [d for d in dirnames if d not in excluded]
            for fname in filenames:
                full = Path(dirpath) / fname
                try:
                    st = full.lstat()
                except OSError:
                    continue
                # Skip symlinked files unless asked.
                if not self.follow_symlinks and (st.st_mode & 0o170000) == 0o120000:
                    continue
                if st.st_size > cap:
                    continue
                yield full


class Scanner(Protocol):
    name: str

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:  # pragma: no cover
        ...
