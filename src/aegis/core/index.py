"""Shared security index: portable, reusable scan artifacts.

Inspired by JetBrains' Shared Indexes (build once, reuse across machines), but
applied to *security* analysis: hashes, secret fingerprints, suspicious-pattern
hits, dependency manifests. The index is a SQLite file (single, copyable) so
teammates can ship a pre-computed audit baseline and skip recomputation.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    mtime REAL NOT NULL,
    mime TEXT,
    indexed_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    scanner TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    line INTEGER,
    fingerprint TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(scanner, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_path ON findings(path);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


@dataclasses.dataclass
class Finding:
    path: str
    scanner: str
    rule: str
    severity: str
    line: int | None
    fingerprint: str
    details: dict[str, Any]


def fingerprint(*parts: str) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8", errors="replace"))
        h.update(b"\x00")
    return h.hexdigest()[:24]


@dataclasses.dataclass
class Index:
    db_path: Path

    def __post_init__(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)",
                ("schema_version", "1"),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                ("last_open", str(time.time())),
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def upsert_file(
        self, path: str, size: int, sha256: str, mtime: float, mime: str | None
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO files(path,size,sha256,mtime,mime,indexed_at)
                   VALUES(?,?,?,?,?,?)
                   ON CONFLICT(path) DO UPDATE SET
                     size=excluded.size,
                     sha256=excluded.sha256,
                     mtime=excluded.mtime,
                     mime=excluded.mime,
                     indexed_at=excluded.indexed_at""",
                (path, size, sha256, mtime, mime, time.time()),
            )

    def add_finding(self, f: Finding) -> bool:
        with self._conn() as conn:
            try:
                conn.execute(
                    """INSERT INTO findings(path,scanner,rule,severity,line,
                       fingerprint,details,created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        f.path,
                        f.scanner,
                        f.rule,
                        f.severity,
                        f.line,
                        f.fingerprint,
                        json.dumps(f.details, ensure_ascii=False, sort_keys=True),
                        time.time(),
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def findings(
        self, severity: str | None = None, scanner: str | None = None
    ) -> Iterable[dict[str, Any]]:
        q = "SELECT * FROM findings WHERE 1=1"
        args: list[Any] = []
        if severity:
            q += " AND severity = ?"
            args.append(severity)
        if scanner:
            q += " AND scanner = ?"
            args.append(scanner)
        q += " ORDER BY severity DESC, path ASC"
        with self._conn() as conn:
            for row in conn.execute(q, args):
                d = dict(row)
                d["details"] = json.loads(d["details"])
                yield d

    def stats(self) -> dict[str, Any]:
        with self._conn() as conn:
            files = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            by_sev = {
                row[0]: row[1]
                for row in conn.execute(
                    "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
                )
            }
            return {"files": files, "findings": total, "by_severity": by_sev}
