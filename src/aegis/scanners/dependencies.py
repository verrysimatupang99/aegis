"""Dependency manifest auditor.

Defensive checks across common ecosystems:
- floating version ranges (^, ~, *, "latest") that drag in unreviewed code
- typosquat-suspect names (Levenshtein-1 from popular packages)
- `git:` / `github:` / arbitrary URL deps that bypass the registry
- post-install scripts in npm packages declared at the top level

We never *fetch* anything; we only read manifests.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path

from ..core.index import Finding, fingerprint
from .base import ScanContext


POPULAR_NPM = {
    "react", "lodash", "express", "axios", "chalk", "commander", "yargs",
    "request", "moment", "uuid", "dotenv", "typescript",
}


def _lev1(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if a == b:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = j = diff = 0
    while i < len(short) and j < len(long_):
        if short[i] != long_[j]:
            diff += 1
            if diff > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return True


class DependencyScanner:
    name = "dependencies"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.iter_files():
            if path.name == "package.json":
                yield from self._scan_npm(path)

    def _scan_npm(self, path: Path) -> Iterable[Finding]:
        try:
            doc = json.loads(path.read_text("utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return

        deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            section = doc.get(key) or {}
            if isinstance(section, dict):
                deps.update({str(k): str(v) for k, v in section.items()})

        for name, spec in deps.items():
            if re.match(r"^(git\+|github:|http[s]?:|file:)", spec):
                yield Finding(
                    path=str(path),
                    scanner=self.name,
                    rule="non_registry_dep",
                    severity="high",
                    line=None,
                    fingerprint=fingerprint(self.name, "non_registry", name, spec),
                    details={"name": name, "spec": spec},
                )

            if spec in {"*", "latest"} or spec.startswith(("^", "~")):
                yield Finding(
                    path=str(path),
                    scanner=self.name,
                    rule="floating_version",
                    severity="low",
                    line=None,
                    fingerprint=fingerprint(self.name, "floating", name, spec),
                    details={"name": name, "spec": spec},
                )

            for popular in POPULAR_NPM:
                if _lev1(name, popular):
                    yield Finding(
                        path=str(path),
                        scanner=self.name,
                        rule="typosquat_suspect",
                        severity="high",
                        line=None,
                        fingerprint=fingerprint(self.name, "typosquat", name, popular),
                        details={"name": name, "looks_like": popular},
                    )
                    break

        scripts = doc.get("scripts") or {}
        for sname in ("preinstall", "install", "postinstall"):
            if sname in scripts:
                yield Finding(
                    path=str(path),
                    scanner=self.name,
                    rule="install_hook",
                    severity="medium",
                    line=None,
                    fingerprint=fingerprint(self.name, "install_hook", sname, str(path)),
                    details={"hook": sname, "command": scripts[sname]},
                )
