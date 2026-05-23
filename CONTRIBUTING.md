# Contributing to Aegis

Thanks for your interest in helping. Aegis is intentionally narrow —
defensive security tooling, charter-bound — so contribution scope is also
narrow. That keeps reviews fast.

## Scope

In-scope contributions:

- **Scanners**: a new scanner plus passing tests, per the protocol in
  `src/aegis/scanners/base.py`. Heuristics that produce zero false
  positives on the dogfood scan are strongly preferred.
- **Bug fixes** with a regression test.
- **Documentation** improvements, especially around client setup.
- **Eval fixtures**: more cases for `eval/fixtures/`. Each case must include
  `input/` plus `expected.json` with `expected_findings` and
  `forbidden_findings`.
- **LLM-advise prompts**: more CVE-derived rubric prompts in
  `eval/llm_advise/prompts.jsonl`. Defensive remediation only — never
  exploitation steps.

Out-of-scope:

- Anything that loosens the Mythos charter or carves an exception from the
  policy engine for a specific tool.
- Offensive tooling, exploit chains, payloads, ban-tools, or doxing
  features. Aegis refuses these by design.

## Development setup

```bash
git clone https://github.com/verrysimatupang99/aegis
cd aegis
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
pytest -q
python -m eval.run --fixtures eval/fixtures --report eval/last_run.json
```

## Running Aegis on itself

The dogfood test is the fastest way to know your change is safe:

```bash
rm -f data/index.sqlite
aegis scan src --max-bytes 4194304
aegis report
```

A green run produces zero findings on the project source.

## Pull request checklist

- [ ] `pytest -q` passes locally on Python 3.11 and 3.12.
- [ ] `python -m eval.run` is unchanged or improved.
- [ ] If you touched a scanner, you ran the dogfood scan and got zero
  findings (or your finding is a true positive on intentional test
  fixtures only).
- [ ] CHANGELOG.md has a one-line entry under "Unreleased" or a new
  version block.
- [ ] No new dependencies pinned with floating ranges (`*`, `latest`,
  open `^`/`~`) without justification — that violates the
  `floating_version` rule we enforce against others.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Don't open public issues for unpatched
vulnerabilities.

## Coding conventions

- Python ≥ 3.11. Type-annotate public functions.
- No mutable global state. The constitution and journal are the only
  long-lived singletons, both passed in explicitly.
- Every action that touches the filesystem or network must go through
  `policy.check_action(...)`. If you find yourself wanting to skip the
  policy gate, that's a design problem — open an issue first.
- Tests for new code live next to a sibling `tests/test_<module>.py` file.
- Keep diffs focused. Refactors and feature additions in separate PRs.
