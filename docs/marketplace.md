# Publishing Aegis to MCP marketplaces and finding accuracy benchmarks

This is the playbook for getting Aegis listed in MCP server registries and
for sourcing third-party accuracy scoring (the "LLM ranking" piece).

## A. MCP marketplaces

There is no single canonical MCP marketplace yet; instead there are several
curated registries and one-click installers. Submit to all of them.

### 1. Anthropic's MCP server registry

- Repo to PR against: `github.com/modelcontextprotocol/servers`
- Add an entry to the README pointing at our repo with a one-line summary.
- Requirements they enforce: server runs over stdio, has a README with
  install + config, exposes a clear scope. Aegis already satisfies all three.

### 2. Smithery (smithery.ai)

- One-click install index for MCP servers. Aggregated by community.
- Submission: open a PR at `github.com/smithery-ai/registry` with a
  `servers/aegis.json` manifest. Fields: `name`, `description`, `homepage`,
  `command`, `transport: stdio`, `category: security`.

### 3. Pulse (pulsemcp.com)

- Browse-and-discover style. They scrape GitHub topics `mcp` + `mcp-server`.
- Action: tag the GitHub repo with topics `mcp`, `mcp-server`, `security`,
  `claude`, `codex`. Add a `mcp.json` manifest at the repo root for their
  scraper.

### 4. mcp.so

- Mirror of public MCP servers, alphabetical.
- Auto-listed when the repo has the topics above.

### 5. Glama (glama.ai/mcp)

- Curated, manually reviewed. Apply via their form. They want a working demo
  recording. Plan to record a 90-second clip of `aegis scan`, `aegis report`,
  and a Claude Desktop call.

### 6. Codex/OpenAI MCP listings

- OpenAI publishes recommended community servers in the Codex docs. PR
  against the docs repo when they open community contributions.

### Per-marketplace manifest

We keep a single source manifest at `docs/marketplace/manifest.json` and
project it into each registry's required shape with a small script. See that
directory.

## B. Trust signals before submission

Marketplaces don't run our scanners; they evaluate the listing. These are
what reviewers actually look at:

- README clearly says **defensive only** with a refusal scope.
- License (MIT) and SECURITY.md present.
- A green CI badge running `pytest` and `python -m eval.run`.
- `mythos.yaml` referenced from the README so reviewers can audit the rules.
- Versioned releases on PyPI under `aegis-sec`.
- A signed (sigstore / cosign) release artifact - nice-to-have, not blocker.

## C. Where to get accuracy scoring (the LLM-ranking equivalent)

Aegis has two halves with very different evaluation needs.

### Detection layer (deterministic)

This is what the world calls a "static analysis" benchmark. Targets:

| Benchmark                  | Type                            | Fit       |
|----------------------------|---------------------------------|-----------|
| **CyberGym**               | vuln reproduction (open-source) | partial   |
| **OSS-Fuzz Gen Eval**      | bug-finding harness             | adjacent  |
| **OWASP Benchmark v1.2**   | precision/recall on Java SAST   | tangential|
| **secrets-benchmark** (community-curated)  | regex precision/recall   | direct    |
| **MITRE D3FEND**           | technique mapping (not scoring) | metadata  |

Submission path: most accept a JSON report in their schema. Our `eval/run.py`
emits the same shape - we add adapters in `eval/adapters/` per benchmark.

### LLM-mediated layer (the `aegis advise` command)

This is where "LLM Ranking"-style boards actually apply, because the output
quality depends on the model the operator plugged in. Targets:

| Board / project            | What it scores                  | How we plug in            |
|----------------------------|---------------------------------|---------------------------|
| **OpenRouter LLM rankings**| latency + cost + bench scores   | publish a model-agnostic spec |
| **Artificial Analysis**    | speed/quality of LLM endpoints  | reference our advise prompts |
| **lmsys Chatbot Arena**    | human preference                | not directly applicable   |
| **HELM Lite (Stanford)**   | reasoning + safety               | submit security subset    |
| **AISI evaluation suites** | safety / capability             | requires application      |
| **LLM-as-judge bench (community)** | rubric-scored Q&A       | curate 50 CVE prompts     |

Practical plan:

1. Curate 100 prompts grounded in real CVE write-ups (not exploit chains;
   defender-side questions). Store in `eval/llm_advise/prompts.jsonl`.
2. For each prompt, define a rubric (`expected_signals`,
   `forbidden_actions`, `tone_constraints`).
3. Run `aegis advise` with each supported model (Claude, GPT, Gemini, local
   llama) and grade with an LLM-as-judge plus 1 human spot check per 10.
4. Publish results as `eval/llm_advise/leaderboard.json`. Anyone can rerun.

The point is: **we don't claim "Aegis is the smartest model"; we publish a
reproducible board that ranks models *on Aegis tasks*.** That's a more
honest framing than chasing generic LLM leaderboards, and it's exactly the
shape Anthropic used with CyberGym in the Glasswing announcement.

## D. Submission checklist (one-shot)

- [ ] PyPI: `python -m build && twine upload dist/*` under `aegis-sec`.
- [ ] GitHub: tag `v0.1.0`, fill `topics: mcp, mcp-server, security, claude, codex, anthropic, audit`.
- [ ] `SECURITY.md` with disclosure email.
- [ ] CI: `pytest` + `python -m eval.run` on every push.
- [ ] PR to `modelcontextprotocol/servers` README.
- [ ] PR to `smithery-ai/registry` with `servers/aegis.json`.
- [ ] Submit to Glama (form + recording).
- [ ] Demo gif in README.
- [ ] 90-second screen recording in `docs/demo.mp4`.
