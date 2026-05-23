"""Filesystem hygiene scanner.

Catches local issues that don't need a content scan:
- world-writable / setuid binaries inside the project
- absolute symlinks pointing outside the project root
- `.env` / credential files committed alongside source
- backup / swap files left behind
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from pathlib import Path

from ..core.index import Finding, fingerprint
from .base import ScanContext


SECRET_FILE_NAMES = {
    ".env", ".env.local", ".env.production", "credentials", "credentials.json",
    "secrets.yaml", "secrets.yml", "id_rsa", "id_ed25519", "id_ecdsa",
}

BACKUP_SUFFIXES = (".bak", ".swp", "~", ".orig", ".rej")


class FilesystemScanner:
    name = "filesystem"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        root = ctx.root.resolve()
        for path in ctx.iter_files():
            try:
                st = path.lstat()
            except OSError:
                continue

            mode = st.st_mode

            if path.is_symlink():
                try:
                    target = (path.parent / os.readlink(path)).resolve()
                    if root not in target.parents and target != root:
                        yield Finding(
                            path=str(path),
                            scanner=self.name,
                            rule="symlink_escapes_root",
                            severity="medium",
                            line=None,
                            fingerprint=fingerprint(self.name, "symlink", str(path)),
                            details={"target": str(target)},
                        )
                except OSError:
                    pass

            if mode & stat.S_ISUID:
                yield Finding(
                    path=str(path),
                    scanner=self.name,
                    rule="setuid_in_project",
                    severity="high",
                    line=None,
                    fingerprint=fingerprint(self.name, "setuid", str(path)),
                    details={"mode": oct(mode)},
                )

            if mode & stat.S_IWOTH:
                yield Finding(
                    path=str(path),
                    scanner=self.name,
                    rule="world_writable",
                    severity="medium",
                    line=None,
                    fingerprint=fingerprint(self.name, "wwrite", str(path)),
                    details={"mode": oct(mode)},
                )

            if path.name in SECRET_FILE_NAMES:
                yield Finding(
                    path=str(path),
                    scanner=self.name,
                    rule="committed_secret_file",
                    severity="high",
                    line=None,
                    fingerprint=fingerprint(self.name, "secret_file", str(path)),
                    details={"name": path.name},
                )

            if any(path.name.endswith(s) for s in BACKUP_SUFFIXES):
                yield Finding(
                    path=str(path),
                    scanner=self.name,
                    rule="backup_artifact",
                    severity="low",
                    line=None,
                    fingerprint=fingerprint(self.name, "backup", str(path)),
                    details={"name": path.name},
                )
