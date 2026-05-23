"""Mythos constitution loader and enforcer.

The constitution is a YAML document that declares hard rules (BLOCK on
violation) and soft rules (WARN on violation). It is loaded once at startup
and treated as immutable for the process lifetime; reload requires a new
process.
"""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from typing import Any

import yaml


@dataclasses.dataclass(frozen=True)
class Rule:
    id: str
    description: str
    hard: bool


@dataclasses.dataclass(frozen=True)
class Constitution:
    version: int
    identity: dict[str, Any]
    hard_rules: tuple[Rule, ...]
    soft_rules: tuple[Rule, ...]
    network_allowlist: tuple[str, ...]
    journal_path: Path
    journal_rotate_mb: int
    fingerprint: str
    source_path: Path

    def rule(self, rule_id: str) -> Rule | None:
        for r in self.hard_rules + self.soft_rules:
            if r.id == rule_id:
                return r
        return None

    def host_allowed(self, host: str) -> bool:
        return host in self.network_allowlist


class ConstitutionError(RuntimeError):
    pass


def load(path: str | Path) -> Constitution:
    p = Path(path).resolve()
    if not p.is_file():
        raise ConstitutionError(f"constitution not found: {p}")
    raw = p.read_bytes()
    fp = hashlib.sha256(raw).hexdigest()[:16]
    doc = yaml.safe_load(raw) or {}
    if doc.get("version") != 1:
        raise ConstitutionError("unsupported constitution version")

    def _rules(key: str, hard: bool) -> tuple[Rule, ...]:
        out: list[Rule] = []
        for entry in doc.get(key) or []:
            if "id" not in entry or "description" not in entry:
                raise ConstitutionError(f"malformed rule in {key}: {entry!r}")
            out.append(
                Rule(
                    id=str(entry["id"]),
                    description=str(entry["description"]).strip(),
                    hard=hard,
                )
            )
        return tuple(out)

    journal = doc.get("journal") or {}
    network = doc.get("network") or {}

    return Constitution(
        version=int(doc["version"]),
        identity=dict(doc.get("identity") or {}),
        hard_rules=_rules("hard_rules", True),
        soft_rules=_rules("soft_rules", False),
        network_allowlist=tuple(network.get("allowlist") or ()),
        journal_path=Path(journal.get("path", ".aegis/journal")),
        journal_rotate_mb=int(journal.get("rotate_mb", 16)),
        fingerprint=fp,
        source_path=p,
    )


def default_path(start: Path | None = None) -> Path:
    here = (start or Path.cwd()).resolve()
    for parent in [here, *here.parents]:
        cand = parent / "data" / "mythos.yaml"
        if cand.is_file():
            return cand
    raise ConstitutionError("could not locate data/mythos.yaml")
