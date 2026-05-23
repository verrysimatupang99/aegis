"""Tests for the LLM-as-judge phase 2 pipeline (mock provider)."""

from __future__ import annotations

import json
from pathlib import Path

from eval.llm_advise.runner import run as run_advise
from eval.llm_advise.judge import parse_judge_text, run_judge


REPO = Path(__file__).resolve().parents[1]


def test_parse_judge_text_extracts_clean_json() -> None:
    raw = '{"accuracy": 4, "defensiveness": 5, "specificity": 3, "leak": "no", "comment": "ok"}'
    out = parse_judge_text(raw)
    assert out["accuracy"] == 4
    assert out["defensiveness"] == 5
    assert out["specificity"] == 3
    assert out["leak"] is False


def test_parse_judge_text_recovers_from_prose_wrapping() -> None:
    raw = (
        "Here is my evaluation:\n"
        '{"accuracy": 2, "defensiveness": 5, "specificity": 1, "leak": "yes", "comment": "x"}\n'
        "trailing text"
    )
    out = parse_judge_text(raw)
    assert out["accuracy"] == 2
    assert out["leak"] is True


def test_parse_judge_text_clamps_out_of_range() -> None:
    raw = '{"accuracy": 99, "defensiveness": -3, "specificity": 5, "leak": "no", "comment": ""}'
    out = parse_judge_text(raw)
    assert out["accuracy"] == 5
    assert out["defensiveness"] == 1


def test_judge_pipeline_with_mock(tmp_path: Path) -> None:
    advise_out = tmp_path / "advise.json"
    summary = run_advise(
        prompts_path=REPO / "eval" / "llm_advise" / "prompts.jsonl",
        out_path=advise_out,
        model_spec="mock:default",
    )
    assert summary["case_count"] == 10
    advise_doc = json.loads(advise_out.read_text("utf-8"))
    assert advise_doc["results"][0]["response_text"]

    judge_out = tmp_path / "judged.json"
    judged = run_judge(advise_out, judge_out, judge_spec="mock:strict")
    assert judged["judged_count"] == 10
    assert judged["avg_accuracy"] == 4.0
    assert judged["avg_defensiveness"] == 5.0
    assert judged["leak_count"] == 0
    on_disk = json.loads(judge_out.read_text("utf-8"))
    assert "judge" in on_disk["results"][0]
    assert on_disk["results"][0]["judge"]["accuracy"] == 4
