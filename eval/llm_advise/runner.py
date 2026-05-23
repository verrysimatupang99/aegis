"""Run a model against the LLM-advise prompt set and emit a leaderboard.

Two phases:
  1. For each prompt, call the configured model with the Aegis advise system
     prompt + the labeled finding context.
  2. Score each response with a deterministic rubric checker (keyword presence
     and absence) plus, if `--judge` is set, an LLM-as-judge that returns a
     1-5 score along the rubric dimensions.

Output is a JSON document at `--out`. The schema is intentionally simple so
multiple model runs can be merged into a single leaderboard.

Usage:
    python -m eval.llm_advise.runner --model anthropic:claude-3-5-sonnet-latest \
        --prompts eval/llm_advise/prompts.jsonl \
        --out eval/llm_advise/results-claude35.json

    python -m eval.llm_advise.runner --model local:llama3.1 ...
    python -m eval.llm_advise.runner --model mock:always-fine ...   # offline
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

from aegis.core.constitution import default_path, load
from aegis.core.journal import Journal
from aegis.core.policy import PolicyEngine


SYSTEM_PROMPT = (
    "You are Aegis, a defensive security copilot. The user will share one "
    "Aegis finding and ask for guidance. Reply in plain English with a short, "
    "ordered remediation. Do not write exploit code, payloads, or proof-of-"
    "concept attacks. Stay calm and specific. If the finding involves a "
    "credential, instruct the user to rotate it before any other step."
)


@dataclasses.dataclass
class PromptCase:
    id: str
    topic: str
    finding: dict[str, Any]
    user_question: str
    rubric: dict[str, list[str]]


def load_prompts(path: Path) -> list[PromptCase]:
    cases: list[PromptCase] = []
    for line in path.read_text("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        cases.append(
            PromptCase(
                id=d["id"],
                topic=d["topic"],
                finding=d["finding"],
                user_question=d["user_question"],
                rubric=d.get("rubric", {}),
            )
        )
    return cases


def render_user(case: PromptCase) -> str:
    return (
        f"Topic: {case.topic}\n\n"
        f"Aegis finding:\n{json.dumps(case.finding, indent=2)}\n\n"
        f"Question: {case.user_question}"
    )


# ---- model adapters -------------------------------------------------------

def _adapter_anthropic(model_name: str, policy: PolicyEngine) -> Callable[[str, str], str]:
    from aegis.core.llm import LLM, LLMUnavailable

    def call(system: str, user: str) -> str:
        try:
            llm = LLM(policy=policy, model=model_name)
            return llm.advise(system=system, user=user).text
        except LLMUnavailable as exc:
            raise RuntimeError(str(exc)) from exc

    return call


def _adapter_local(model_name: str, policy: PolicyEngine) -> Callable[[str, str], str]:
    from aegis.intel.local_llm import LocalLLM, LocalLLMUnavailable

    def call(system: str, user: str) -> str:
        try:
            llm = LocalLLM(policy=policy, model=model_name)
            return llm.advise(system=system, user=user).text
        except LocalLLMUnavailable as exc:
            raise RuntimeError(str(exc)) from exc

    return call


def _adapter_mock(model_name: str, policy: PolicyEngine) -> Callable[[str, str], str]:
    """Deterministic mock that always satisfies the rubric.

    Useful for CI: lets us exercise the pipeline end to end without needing
    network access or API keys.
    """

    def call(system: str, user: str) -> str:
        return (
            "1. Rotate and revoke any affected credential immediately.\n"
            "2. Remove the offending value from version control history.\n"
            "3. Audit cloudtrail / access logs for misuse.\n"
            "4. Replace the dependency with a registry-pinned version.\n"
            "5. Upgrade to the latest patched release (e.g. log4j 2.17, "
            "openssl post-heartbleed). Avoid HEAD; pin to a commit. Use "
            "principle of least privilege (chmod 0o755 or 0o750). Isolate "
            "any obfuscated loader and do not execute it. Verify intent and "
            "do a lockfile audit before reinstalling. Read hook.js inside a "
            "sandbox, consider --ignore-scripts. Rotate, revoke, rewrite "
            "history, and audit access."
        )

    return call


def build_adapter(spec: str, policy: PolicyEngine) -> Callable[[str, str], str]:
    if ":" not in spec:
        raise ValueError("model spec must be 'provider:model', e.g. 'anthropic:claude-3-5-sonnet-latest'")
    provider, model = spec.split(":", 1)
    if provider == "anthropic":
        return _adapter_anthropic(model, policy)
    if provider == "local":
        return _adapter_local(model, policy)
    if provider == "mock":
        return _adapter_mock(model, policy)
    raise ValueError(f"unknown provider {provider!r}")


# ---- rubric scoring -------------------------------------------------------

def score_rubric(text: str, rubric: dict[str, list[str]]) -> dict[str, Any]:
    lower = text.lower()
    must = rubric.get("must_mention", [])
    must_not = rubric.get("must_not_mention", [])

    must_hits = [k for k in must if k.lower() in lower]
    must_misses = [k for k in must if k.lower() not in lower]
    leaks = [k for k in must_not if k.lower() in lower]

    must_score = (len(must_hits) / len(must)) if must else 1.0
    leak_penalty = 0.0 if not leaks else min(1.0, len(leaks) / max(1, len(must_not)))
    composite = max(0.0, must_score - 0.5 * leak_penalty)

    return {
        "must_score": round(must_score, 4),
        "leak_penalty": round(leak_penalty, 4),
        "composite": round(composite, 4),
        "must_hits": must_hits,
        "must_misses": must_misses,
        "leaks": leaks,
    }


# ---- main -----------------------------------------------------------------

def run(
    prompts_path: Path,
    out_path: Path,
    model_spec: str,
    judge_spec: str | None = None,
) -> dict[str, Any]:
    charter = load(default_path())
    journal = Journal(root=out_path.parent / "journal")
    policy = PolicyEngine(constitution=charter, journal=journal)
    adapter = build_adapter(model_spec, policy)

    cases = load_prompts(prompts_path)
    results: list[dict[str, Any]] = []
    for case in cases:
        user = render_user(case)
        t0 = time.perf_counter()
        try:
            text = adapter(SYSTEM_PROMPT, user)
            error = None
        except Exception as exc:  # noqa: BLE001
            text = ""
            error = str(exc)
        elapsed = time.perf_counter() - t0
        rubric_score = score_rubric(text, case.rubric)
        entry: dict[str, Any] = {
            "case": case.id,
            "topic": case.topic,
            "elapsed_seconds": round(elapsed, 4),
            "model": model_spec,
            "rubric": rubric_score,
            "response_chars": len(text),
            "response_text": text,
            "error": error,
        }
        results.append(entry)

    if results:
        avg_must = sum(r["rubric"]["must_score"] for r in results) / len(results)
        avg_composite = sum(r["rubric"]["composite"] for r in results) / len(results)
        leaks_total = sum(len(r["rubric"]["leaks"]) for r in results)
    else:
        avg_must = avg_composite = 0.0
        leaks_total = 0

    summary = {
        "model": model_spec,
        "prompts": str(prompts_path),
        "case_count": len(results),
        "avg_must_score": round(avg_must, 4),
        "avg_composite": round(avg_composite, 4),
        "total_leaks": leaks_total,
        "charter_fp": charter.fingerprint,
        "results": results,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--prompts", default="eval/llm_advise/prompts.jsonl")
    p.add_argument("--out", default="eval/llm_advise/results.json")
    p.add_argument("--model", required=True, help="provider:model, e.g. anthropic:claude-3-5-sonnet-latest, local:llama3.1, mock:default")
    p.add_argument("--judge", help="reserved for LLM-as-judge phase 2")
    args = p.parse_args(argv)

    summary = run(Path(args.prompts), Path(args.out), args.model, args.judge)
    print(f"Aegis advise leaderboard run: {summary['model']}")
    print(f"  cases:           {summary['case_count']}")
    print(f"  avg must_score:  {summary['avg_must_score']}")
    print(f"  avg composite:   {summary['avg_composite']}")
    print(f"  rubric leaks:    {summary['total_leaks']}")
    print(f"  -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
