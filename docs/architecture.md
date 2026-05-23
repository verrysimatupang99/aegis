# Aegis Architecture

## Trust boundary

```
   user input ──┐
   filesystem ──┼─▶ scanners ──▶ findings ──▶ index (SQLite)
   network    ──┘                    │
                                     ▼
                                  journal (JSONL)
                                     ▲
                                     │
   policy engine ◀── constitution (mythos.yaml, hashed in memory)
        ▲
        │ every action passes through here
   ┌────┴────┐
   │  CLI    │
   │  LLM    │
   │  MCP    │
   └─────────┘
```

The policy engine is the only path to side effects. Scanners read; the engine
authorizes. There is no back-channel from a scanner to the network or to a
destructive operation.

## Why a SQLite "shared index"

A scan that walks a million files is expensive. JetBrains solved that for IDE
indexing by letting one machine build the index and shipping the artifact to
the team. Aegis does the same for security:

- one row per file in `files` (path, size, sha256, mtime)
- one row per finding in `findings` (deduplicated by `(scanner, fingerprint)`)
- a single `meta` table for schema version

Two operators can compare baselines by `diff`-ing their index files; CI can
fail a build when a high-severity finding appears that wasn't in the prior
baseline.

## Why a hashed constitution

Mythos is loaded once, sha256'd, frozen as an immutable dataclass. The
fingerprint is recorded on every journal entry. If someone edits the charter
mid-session you'd see the fingerprint flip in the journal; if a scanned file
tries to inject "ignore previous instructions" the policy engine never reads
text content as instruction in the first place.

## Why the journal is JSONL

- append-only is durable under crash
- one record per line is grep-friendly
- `payload` is redacted (home path stripped, secrets fingerprinted)
- daily rotation + size-based rotation keep files bounded
- replay is `journal.replay()` returning a generator

## Extending

A new scanner is one file:

```python
class MyScanner:
    name = "myscan"
    def scan(self, ctx):
        for path in ctx.iter_files():
            yield Finding(path=str(path), scanner=self.name, ...)
```

Add it to `aegis.core.runner.all_scanners()` and it runs through the same
policy + journal + index plumbing.
