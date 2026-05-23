"""Differential gate: compare two Aegis shared indexes.

Usage:
    python -m aegis.cli.diff <baseline.sqlite> <current.sqlite> \
        [--fail-on critical,high] [--json out.json]

Exit code is non-zero when *new* findings of the requested severity appear in
`current` that were not in `baseline`. Useful as a CI gate: commit the
baseline, fail the build when new high/critical issues land.

A finding is matched between indexes by `(scanner, rule, fingerprint)`. The
fingerprint already accounts for path + line + redacted value, so trivial
edits to comments don't change it.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _load_findings(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"index not found: {path}")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    out: dict[str, dict[str, Any]] = {}
    try:
        rows = conn.execute(
            "SELECT scanner, rule, severity, fingerprint, path, line, details FROM findings"
        ).fetchall()
    except sqlite3.OperationalError as exc:
        raise RuntimeError(f"index has no findings table: {path}") from exc
    finally:
        conn.close()
    for r in rows:
        key = f"{r['scanner']}::{r['rule']}::{r['fingerprint']}"
        out[key] = {
            "scanner": r["scanner"],
            "rule": r["rule"],
            "severity": r["severity"],
            "fingerprint": r["fingerprint"],
            "path": r["path"],
            "line": r["line"],
            "details": json.loads(r["details"]),
        }
    return out


def _filter_severities(spec: str | None) -> set[str]:
    if not spec:
        return set()
    return {s.strip() for s in spec.split(",") if s.strip()}


def diff(
    baseline: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    added_keys = current.keys() - baseline.keys()
    removed_keys = baseline.keys() - current.keys()
    common = baseline.keys() & current.keys()
    severity_changed = [
        {
            "key": k,
            "from": baseline[k]["severity"],
            "to": current[k]["severity"],
            "scanner": current[k]["scanner"],
            "rule": current[k]["rule"],
            "path": current[k]["path"],
        }
        for k in common
        if baseline[k]["severity"] != current[k]["severity"]
    ]
    return {
        "added": sorted((current[k] for k in added_keys), key=_sev_key),
        "removed": sorted((baseline[k] for k in removed_keys), key=_sev_key),
        "severity_changed": severity_changed,
    }


def _sev_key(f: dict[str, Any]) -> tuple[int, str]:
    sev = f.get("severity", "info")
    return (
        SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 99,
        f.get("path", ""),
    )


def _print_table(title: str, rows: Iterable[dict[str, Any]]) -> int:
    rows = list(rows)
    print(f"\n{title} ({len(rows)})")
    if not rows:
        print("  (none)")
        return 0
    for r in rows:
        loc = f":{r['line']}" if r.get("line") else ""
        print(f"  [{r['severity']:8}] {r['scanner']}/{r['rule']}  {r['path']}{loc}")
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegis-diff")
    p.add_argument("baseline", type=Path)
    p.add_argument("current", type=Path)
    p.add_argument(
        "--fail-on",
        default="critical,high",
        help="comma-separated severities that fail the gate when newly added",
    )
    p.add_argument("--json", type=Path, help="write the diff to JSON")
    args = p.parse_args(argv)

    baseline = _load_findings(args.baseline)
    current = _load_findings(args.current)
    result = diff(baseline, current)

    _print_table("Added findings", result["added"])
    _print_table("Removed findings", result["removed"])
    print(f"\nSeverity changed ({len(result['severity_changed'])})")
    for c in result["severity_changed"]:
        print(f"  {c['scanner']}/{c['rule']}  {c['from']} -> {c['to']}  {c['path']}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        print(f"\nwrote {args.json}")

    fail_severities = _filter_severities(args.fail_on)
    bad_added = [f for f in result["added"] if f["severity"] in fail_severities]
    if bad_added:
        print(
            f"\nGATE FAIL: {len(bad_added)} new findings at severity in {sorted(fail_severities)}",
            file=sys.stderr,
        )
        return 1
    print("\nGATE PASS: no new findings at gating severities")
    return 0


if __name__ == "__main__":
    sys.exit(main())
