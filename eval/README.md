# Aegis evaluation harness

This harness produces a reproducible accuracy report for Aegis. It is what we
ship to leaderboards (e.g. LLM-Ranking-style benchmarks) when claiming
detection quality.

## What we measure

- **Precision / Recall / F1** per scanner per rule, against a labeled fixture
  corpus (`fixtures/`).
- **Time-to-finding** wall clock per scan.
- **Charter compliance**: every action recorded in the journal is checked to
  have a matching `policy.decision` entry. Drift = bug.
- **MCP latency**: round-trip time for each tool over stdio.

We deliberately do not score "how good is the LLM at writing remediation".
That depends on the model the operator plugs in. Our scope is the deterministic
detection layer plus the policy gate.

## Fixture format

Each fixture is a directory with:

```
fixtures/<case-name>/
  input/                  # files to scan
  expected.json           # labeled ground truth
```

`expected.json` shape:

```json
{
  "expected_findings": [
    {"scanner": "secrets", "rule": "github_pat", "path_glob": "input/*.env"},
    {"scanner": "obfuscation", "rule": "obfuscated_loader", "path_glob": "input/*.js"}
  ],
  "forbidden_findings": [
    {"scanner": "secrets", "rule": "openai_key", "path_glob": "input/clean.txt"}
  ]
}
```

The harness counts:

- **TP** = expected finding matched.
- **FN** = expected finding not produced.
- **FP** = produced finding that violates `forbidden_findings` or hits a
  fixture path not in `expected_findings`.

## Running

```bash
python -m eval.run --fixtures eval/fixtures --report eval/last_run.json
```

Output is a single JSON report we can submit to a leaderboard or check into
git for diffing.

## Where to publish results

We're tracking a few options for public, third-party scored evaluation:

- **CyberGym** (used in the Anthropic Glasswing announcement) - vulnerability
  reproduction; not a perfect fit for our detection scope but the closest
  open-source benchmark to the marketing surface we care about.
- **OpenSSF Scorecard** - automated, reproducible scoring of OSS projects.
  Not detection quality per se, but a credibility signal.
- **MITRE D3FEND mappings** - we tag each rule with a D3FEND technique ID so
  defenders can correlate Aegis findings with their existing taxonomy.
- **Detection Engineering Maturity benchmarks** (community-maintained) - we
  contribute our YARA + heuristic rules and measure detection latency.

We avoid generic "LLM leaderboards" (Chatbot Arena, MMLU, etc.) for the
detection layer because Aegis is mostly deterministic. We do plan to publish
a *separate* eval for `aegis advise` (the LLM-mediated remediation step)
against a curated set of CVE-derived prompts, scored by humans with rubrics.
