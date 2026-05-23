# Connecting Aegis to MCP clients

Aegis is published to the MCP Registry as
`io.github.verrysimatupang99/aegis` and to PyPI as `aegis-sec`. You don't
need to clone this repo to use it.

## Recommended: `uvx` one-liner

[`uv`](https://docs.astral.sh/uv/) (or `uvx`) installs the package into a
disposable virtualenv on demand. Same shape works in every MCP client:

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

If you want to scan a specific project, set the `AEGIS_HOME` env var so the
journal and the SQLite index land inside that project:

```jsonc
{
  "mcpServers": {
    "aegis": {
      "command": "uvx",
      "args": ["--from", "aegis-sec", "aegis-mcp"],
      "env": { "AEGIS_HOME": "/path/to/your/project" }
    }
  }
}
```

## Alternative: `pip install`

```bash
pipx install aegis-sec        # or: pip install --user aegis-sec
which aegis-mcp               # confirm it's on PATH
```

```jsonc
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp"
    }
  }
}
```

## Per-client paths

| Client                | Config file                                                                  |
|-----------------------|------------------------------------------------------------------------------|
| Claude Desktop (mac)  | `~/Library/Application Support/Claude/claude_desktop_config.json`            |
| Claude Desktop (Win)  | `%APPDATA%\Claude\claude_desktop_config.json`                                |
| Claude Code           | `~/.config/claude-code/mcp.json` (or repo-scoped `.mcp.json`)                |
| Codex CLI / Desktop   | `~/.codex/mcp.json` (key is `servers`, not `mcpServers`)                     |
| Cursor                | Settings → MCP                                                               |
| Continue              | `~/.continue/config.yaml` under `mcpServers`                                 |
| Zed                   | `~/.config/zed/settings.json` under `context_servers`                        |

Codex uses a slightly different shape:

```jsonc
{
  "servers": {
    "aegis": {
      "command": "uvx",
      "args": ["--from", "aegis-sec", "aegis-mcp"],
      "transport": "stdio"
    }
  }
}
```

After saving, restart the client. Aegis tools appear under the hammer icon
(Claude Desktop / Code) or the MCP panel (Cursor / Codex).

## Verifying

Ask the model:

> Use the `show_charter` tool from aegis.

You should see the charter fingerprint and the list of hard rules. Then:

> Run `scan_path` against /path/to/some/repo and report critical findings.

Every call passes through the policy engine and is journaled to
`$AEGIS_HOME/.aegis/journal/`.

## Tools exposed

| Tool             | Purpose                                                |
|------------------|--------------------------------------------------------|
| `scan_path`      | Walk a directory, run all scanners, write findings.    |
| `report_findings`| Pull findings from the shared index, optional filter.  |
| `explain_finding`| Plain-English remediation hint for one fingerprint.    |
| `show_charter`   | Active Mythos constitution + fingerprint.              |
| `tail_journal`   | Recent Glasswing journal entries.                      |

## Resources exposed

| URI                    | Purpose                                  |
|------------------------|------------------------------------------|
| `aegis://charter`      | Read-only YAML of the active charter.    |
| `aegis://index/stats`  | JSON counts of files + findings.         |
