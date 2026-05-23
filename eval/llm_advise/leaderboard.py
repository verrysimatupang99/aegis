"""Merge multiple llm-advise result files into a single leaderboard.

Usage:
    python -m eval.llm_advise.leaderboard \
        eval/llm_advise/results-*.json \
        --out eval/llm_advise/leaderboard.json

Output is a markdown-friendly JSON the README + the marketplace listing can
embed: one row per model, sorted by composite score.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("results", nargs="+", help="result JSON files from eval.llm_advise.runner")
    p.add_argument("--out", default="eval/llm_advise/leaderboard.json")
    args = p.parse_args(argv)

    rows: list[dict[str, Any]] = []
    for path_str in args.results:
        path = Path(path_str)
        if not path.is_file():
            print(f"skip: {path} (not a file)", file=sys.stderr)
            continue
        doc = json.loads(path.read_text("utf-8"))
        rows.append(
            {
                "model": doc.get("model"),
                "case_count": doc.get("case_count"),
                "avg_must_score": doc.get("avg_must_score"),
                "avg_composite": doc.get("avg_composite"),
                "total_leaks": doc.get("total_leaks"),
                "source": str(path),
            }
        )

    rows.sort(key=lambda r: (-(r.get("avg_composite") or 0), r.get("total_leaks") or 0))

    table_md = ["| Rank | Model | Composite | Must-score | Leaks | Cases |",
                "|------|-------|-----------|------------|-------|-------|"]
    for i, r in enumerate(rows, 1):
        table_md.append(
            f"| {i} | `{r['model']}` | {r['avg_composite']} | "
            f"{r['avg_must_score']} | {r['total_leaks']} | {r['case_count']} |"
        )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps({"rows": rows, "table_markdown": table_md}, indent=2),
        encoding="utf-8",
    )

    print("Aegis llm-advise leaderboard")
    for line in table_md:
        print(line)
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
