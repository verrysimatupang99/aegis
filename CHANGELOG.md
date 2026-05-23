# Changelog

All notable changes to Aegis are documented here. Format is loosely
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] — 2026-05-23

### Added
- `--exclude` flag on `aegis scan` (repeatable). Skip directory names by
  basename match against any path component, on top of the defaults.
- Default excluded directories now also cover `target` (Rust/Tauri),
  `.next`, `.nuxt`, `.turbo`, `.parcel-cache`, `vendor`, `coverage`,
  `.cache`, `.gradle`, `.idea`, `.pytest_cache`, `.mypy_cache`,
  `.ruff_cache`, `site-packages`, `gen`, `artifacts`, and `models`.
  Whole-workspace scans (e.g. `aegis scan ~/Documents/Coding`) skip the
  GB-scale build/cache trees by default.

### Tests
- New `tests/test_exclude_flag.py` (2 tests): verify defaults include the
  new dirs, and that `--exclude` skips matching path components.

## [0.1.1] — 2026-05-23

### Fixed
- **Dockerfile scanner** no longer matches code or doc files such as
  `dockerfile.py`, `dockerfile.md`, `dockerfile.json`. Only true
  Dockerfile-family names match.
- **Obfuscation scanner** scope tightened to JS-family suffixes only
  (`.js`, `.mjs`, `.cjs`, `.ts`). Python and shell sources are no longer
  scanned for JS-loader heuristics.
- **Obfuscation scanner** parenthesised the `self_extract` heuristic so
  the precedence between `or` and `and` is unambiguous.

### Reliability
- Runner isolates scanner exceptions; one crashing scanner no longer
  aborts the whole run. Errors are journaled as `scan.scanner_error`.
- Index opens SQLite with `journal_mode=WAL` and `synchronous=NORMAL` so
  the MCP server and the CLI can read concurrently without locking.

### Tests
- Added `tests/test_dogfood_regression.py` (3 tests) pinning the dockerfile
  heuristic, asserting Aegis self-scan yields zero findings, and
  verifying scanner isolation under exception.

## [0.1.0] — 2026-05-23

Initial public release.

### Highlights
- Constitution-bound (Mythos charter) policy engine, single chokepoint
  for every tool call.
- Glasswing journal: append-only redacted JSONL audit trail.
- Shared SQLite index, JetBrains-style portable artifact.
- 7 scanners: secrets, obfuscation, dependencies, filesystem, Dockerfile,
  IaC, optional YARA.
- MCP stdio server (Claude Desktop, Claude Code, Codex CLI/Desktop,
  Cursor, Continue, Zed).
- LLM adapters: Anthropic, local Ollama, deterministic mock.
- Differential gate (`aegis-diff`) for CI severity drift detection.
- Evaluation harness: deterministic fixtures + LLM-advise + LLM-as-judge
  phase 2.
- CI: pytest matrix (py3.11/3.12), eval harness, PR diff comment,
  sigstore-signed PyPI release.
