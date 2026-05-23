<!-- mcp-name: io.github.verrysimatupang99/aegis -->

# Aegis

[![PyPI](https://img.shields.io/pypi/v/aegis-sec?label=aegis-sec)](https://pypi.org/project/aegis-sec/)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.verrysimatupang99%2Faegis-7c3aed)](https://registry.modelcontextprotocol.io/v0/servers?search=io.github.verrysimatupang99/aegis)
[![CI](https://github.com/verrysimatupang99/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/verrysimatupang99/aegis/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)


A transparent, constitution-bound defensive security copilot. Ships a CLI, an
MCP server (Claude Desktop, Claude Code, Codex CLI/Desktop, Cursor, Continue,
Zed), an optional cloud or local LLM advisor, an HTML report exporter, and an
evaluation harness.

```
aegis scan ~/some/repo
aegis report --severity critical --html out/report.html
aegis-mcp                                # stdio MCP server
```

## Why this exists

This project is the inverse of an obfuscated abuse toolkit: defensive only,
inspectable by design, and bound by a charter the agent cannot rewrite.

Three ideas guide it:

- **Project Glasswing (Anthropic)** - defensive collaboration and shareable
  security artifacts. Aegis stores findings as a portable SQLite index and
  records every decision in an append-only journal.
- **Claude Mythos** - the constitution-as-character idea. Aegis loads
  `data/mythos.yaml`, hashes it, and refuses to act outside its hard rules.
- **JetBrains Shared Indexes** - heavy analysis, computed once, shared. Aegis
  ships its index in the same shape so a teammate can clone the audit
  baseline without re-scanning.

## Layout

```
src/aegis/
  core/            constitution, journal, policy gate, shared index, llm
  scanners/        secrets, obfuscation, dependencies, filesystem, yara
  intel/           local_llm, report_html
  cli/main.py      `aegis` command
  mcp/server.py    `aegis-mcp` MCP stdio server
data/mythos.yaml   the charter; edit to harden, not to weaken
data/yara/         bundled YARA rules (used when yara-python is installed)
docs/              architecture, client configs, marketplace playbook
eval/              labeled fixtures + harness producing JSON precision/recall
tests/             pytest suite, including end-to-end MCP dispatch
```

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]              # core + tests
pip install -e .[all]              # core + tests + LLM extras + yara

aegis charter                       # active constitution + fingerprint
aegis scan ~/some/repo              # walk + hash + run all scanners
aegis report --severity critical
aegis report --html out/report.html
aegis advise --severity high        # cloud Claude (needs ANTHROPIC_API_KEY)
aegis advise --severity high --local --model llama3.1
aegis serve mcp                     # stdio MCP for clients
aegis journal --limit 50            # replay every decision
```

The shared index lives at `data/index.sqlite`. Copy it to share an audit
baseline; recipients run `aegis report` against it without rescanning.

## Connecting to MCP clients

Aegis is published to the MCP Registry as
`io.github.verrysimatupang99/aegis` and to PyPI as
[`aegis-sec`](https://pypi.org/project/aegis-sec/). You don't need to clone
this repo to use it. Same shape works in Claude Desktop, Claude Code, Codex,
Cursor, Continue, and Zed:

```jsonc
{
  "mcpServers": {
    "aegis": {
      "command": "uvx",
      "args": ["--from", "aegis-sec", "aegis-mcp"]
    }
  }
}
```

Codex uses `servers` instead of `mcpServers` but the command is identical.
See [`docs/clients/README.md`](docs/clients/README.md) for per-client config
file paths and verification steps.

## Design rules

1. **Defensive only.** The charter blocks any action that resembles spam,
   doxing, exploitation against third parties, or ban tooling.
2. **No silent network.** Outbound calls require a host on the charter
   allowlist or an explicit `--allow-exfil <host>`. Both are journaled.
3. **No secret echoing.** Detected credentials are SHA-256 fingerprinted
   before they touch the index, the journal, or any LLM context.
4. **Reversible first.** Destructive tools require `--i-mean-it`.
5. **Charter immutable at runtime.** Aegis hashes `mythos.yaml` on load and
   treats prompt-injection text in scanned files as data, not orders.

## Smoke test against a known-bad sample

The first thing Aegis was tested on is the obfuscated loader from the toolkit
it replaced. The verdict was unambiguous:

```
[critical] obfuscation/obfuscated_loader  /tmp/arctryx-trash-*/start
    entropy: 11.478
    exotic_ratio: 0.7442
    longest_line: 4_835_152
    signals: long_line, danger_tokens, exotic_unicode, high_entropy,
             self_extract, anti_debug
```

If that archive is still present, `pytest` reruns the smoke test
automatically; otherwise it skips itself.

## Evaluation

```
python -m eval.run --fixtures eval/fixtures --report eval/last_run.json
```

Three fixture cases ship in-tree (secrets, obfuscation, dependencies). Add
your own by dropping `<case>/input/` plus `<case>/expected.json`. The harness
prints precision/recall/F1 per case and aggregate; the JSON output is what we
publish to leaderboards.

See [`docs/marketplace.md`](docs/marketplace.md) for the playbook on getting
Aegis listed in MCP marketplaces and where to source third-party accuracy
benchmarks (the "LLM ranking" piece).


## Differential gate

```bash
aegis scan src                                  # build current index
python -m aegis.cli.diff baseline.sqlite data/index.sqlite \
  --fail-on critical,high
```

Compares two shared indexes by `(scanner, rule, fingerprint)`. The gate exits
non-zero when *new* findings appear at the requested severities. Drop a
`baselines/index.sqlite` in your repo and the bundled GitHub Actions
workflow will run the diff on every PR.

## LLM-advise leaderboard

We do not chase generic LLM leaderboards for the deterministic detection
layer. For the LLM-mediated `aegis advise` step we ship our own reproducible
board:

```bash
# offline smoke (no API key, no network)
python -m eval.llm_advise.runner --model mock:default \
  --out eval/llm_advise/results-mock.json

# any provider that fits the adapter
python -m eval.llm_advise.runner --model anthropic:claude-3-5-sonnet-latest \
  --out eval/llm_advise/results-claude35.json
python -m eval.llm_advise.runner --model local:llama3.1 \
  --out eval/llm_advise/results-llama3.json

python -m eval.llm_advise.leaderboard eval/llm_advise/results-*.json \
  --out eval/llm_advise/leaderboard.json
```

Each model is scored against rubrics in `eval/llm_advise/prompts.jsonl`
(must-mention terms, must-not-mention leaks). The leaderboard table is
markdown-friendly and ready to embed in the repo or marketplace listing.
See [`docs/marketplace.md`](docs/marketplace.md) for the publishing playbook.


## Scanners shipped

| Scanner       | What it catches                                                  |
|---------------|------------------------------------------------------------------|
| `secrets`     | Known-prefix tokens (GH, OpenAI, Anthropic, AWS, Slack, JWT, private keys), entropy-gated. Values redacted to SHA-256. |
| `obfuscation` | Self-extracting JS loaders, exotic-Unicode noise, eval/Function abuse, anti-debug, aes+gunzip pipelines. |
| `dependencies`| Floating npm versions, typosquats (Levenshtein-1), non-registry deps, install hooks. |
| `filesystem`  | World-writable, setuid in project, escaping symlinks, committed credential files, backup artifacts. |
| `dockerfile`  | `FROM :latest`, runs as root, secrets in ENV/ARG, `curl|sh`, `chmod 777`, `ADD` with remote URL. |
| `iac`         | Terraform: public S3 ACL, open 0.0.0.0/0 ingress, literal secrets. GitHub Actions: `pull_request_target`, unpinned `uses:@branch`, `curl|sh` in run blocks. |
| `yara`        | Optional, opt-in (`pip install -e .[yara]`). Bundles 3 rules; you drop more in `data/yara/`. |

## CI integration

- `.github/workflows/ci.yml` runs `pytest` + `eval.run` on every push/PR (matrix py3.11+3.12).
- `.github/workflows/pr-comment.yml` posts an Aegis defensive diff as a sticky PR comment, fails the build when new `critical`/`high` findings appear vs `baselines/index.sqlite`.
- `.github/workflows/release.yml` builds, signs with sigstore, and publishes to PyPI via trusted publishing on `v*` tags.

## LLM-as-judge phase 2

After running the rubric scorer, you can score responses with a judge model:

```bash
python -m eval.llm_advise.judge \
  --in  eval/llm_advise/results-claude35.json \
  --out eval/llm_advise/results-claude35.judged.json \
  --judge anthropic:claude-3-5-sonnet-latest

# offline path:
python -m eval.llm_advise.judge \
  --in  eval/llm_advise/results-mock.json \
  --out eval/llm_advise/results-mock.judged.json \
  --judge mock:strict
```

Judge output is a strict JSON: `accuracy`, `defensiveness`, `specificity`
(1-5 each), and an explicit `leak` flag. We aggregate per-model into the
leaderboard.

## Roadmap

- More scanners (Dockerfile hardening, IaC misconfig, browser extension
  manifests, mobile app permissions).
- Differential mode: compare two indexes and surface only newly-introduced
  findings (CI gate).
- Signed releases (sigstore / cosign).
- Web UI on top of the shared index.

## License

MIT.
