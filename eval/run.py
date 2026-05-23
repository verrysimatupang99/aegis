"""Run Aegis against labeled fixtures and emit a precision/recall report.

Usage:
    python -m eval.run --fixtures eval/fixtures --report eval/last_run.json
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import tempfile
import time
from pathlib import Path

from aegis.core.constitution import default_path, load
from aegis.core.index import Index
from aegis.core.journal import Journal
from aegis.core.policy import PolicyEngine
from aegis.core.runner import run_scan


def _match(rule: dict, finding: dict, case_root: Path) -> bool:
    if rule.get("scanner") and rule["scanner"] != finding.get("scanner"):
        return False
    if rule.get("rule") and rule["rule"] != finding.get("rule"):
        return False
    glob = rule.get("path_glob")
    if glob:
        rel = str(Path(finding["path"]).relative_to(case_root)) if case_root in Path(finding["path"]).parents else finding["path"]
        if not fnmatch.fnmatch(rel, glob):
            return False
    return True


def evaluate_case(case_dir: Path, charter_path: Path) -> dict:
    expected_path = case_dir / "expected.json"
    input_dir = case_dir / "input"
    if not expected_path.is_file() or not input_dir.is_dir():
        raise FileNotFoundError(f"malformed fixture: {case_dir}")
    spec = json.loads(expected_path.read_text("utf-8"))
    expected = list(spec.get("expected_findings", []))
    forbidden = list(spec.get("forbidden_findings", []))

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        charter = load(charter_path)
        journal = Journal(root=tmp_path / "journal")
        policy = PolicyEngine(constitution=charter, journal=journal)
        index = Index(db_path=tmp_path / "idx.sqlite")
        t0 = time.perf_counter()
        report = run_scan(root=input_dir, index=index, policy=policy, max_bytes=64 * 1024 * 1024)
        elapsed = time.perf_counter() - t0
        produced = list(index.findings())

    matched_expected: set[int] = set()
    fp = 0
    for f in produced:
        hit_expected = False
        for i, exp in enumerate(expected):
            if i in matched_expected:
                continue
            if _match(exp, f, input_dir):
                matched_expected.add(i)
                hit_expected = True
                break
        if hit_expected:
            continue
        if any(_match(forb, f, input_dir) for forb in forbidden):
            fp += 1
            continue
    tp = len(matched_expected)
    fn = len(expected) - tp
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "case": case_dir.name,
        "elapsed_seconds": round(elapsed, 4),
        "files_indexed": report.files_indexed,
        "findings_produced": len(produced),
        "expected": len(expected),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--fixtures", default="eval/fixtures")
    p.add_argument("--charter", default=None)
    p.add_argument("--report", default="eval/last_run.json")
    args = p.parse_args(argv)

    fixtures_dir = Path(args.fixtures).resolve()
    if not fixtures_dir.is_dir():
        print(f"fixtures dir not found: {fixtures_dir}", file=sys.stderr)
        return 2
    charter_path = Path(args.charter).resolve() if args.charter else default_path()

    cases = sorted(c for c in fixtures_dir.iterdir() if c.is_dir())
    if not cases:
        print("(no fixtures)")
        return 0

    results = [evaluate_case(c, charter_path) for c in cases]
    agg = {
        "cases": len(results),
        "tp": sum(r["true_positives"] for r in results),
        "fp": sum(r["false_positives"] for r in results),
        "fn": sum(r["false_negatives"] for r in results),
    }
    agg["precision"] = round(agg["tp"] / (agg["tp"] + agg["fp"]), 4) if (agg["tp"] + agg["fp"]) else 1.0
    agg["recall"] = round(agg["tp"] / (agg["tp"] + agg["fn"]), 4) if (agg["tp"] + agg["fn"]) else 1.0
    if agg["precision"] + agg["recall"]:
        agg["f1"] = round(2 * agg["precision"] * agg["recall"] / (agg["precision"] + agg["recall"]), 4)
    else:
        agg["f1"] = 0.0

    out = {"aggregate": agg, "cases": results}
    out_path = Path(args.report)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"Aegis eval: {len(results)} cases")
    print(f"  precision={agg['precision']}  recall={agg['recall']}  f1={agg['f1']}")
    for r in results:
        print(f"  - {r['case']:30}  P={r['precision']}  R={r['recall']}  F1={r['f1']}  ({r['elapsed_seconds']}s)")
    print(f"report: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
