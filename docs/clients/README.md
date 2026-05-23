# Connecting Aegis to MCP clients

Aegis ships an MCP server over stdio. Any client that supports MCP stdio
servers can plug it in. The command is the same across all clients:

```
aegis-mcp
```

Set `AEGIS_HOME` to the project root if you run the server from elsewhere
(needed so it can locate `data/mythos.yaml` and the shared index).

The configs below assume Aegis is installed in a virtualenv at
`/opt/aegis/.venv` and the project root is `/opt/aegis`. Adjust paths.

## Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/opt/aegis/.venv/bin/aegis-mcp",
      "args": [],
      "env": {
        "AEGIS_HOME": "/opt/aegis"
      }
    }
  }
}
```

Restart Claude Desktop. The Aegis tools appear under the hammer icon.

## Claude Code (CLI)

Add to `~/.config/claude-code/mcp.json`:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/opt/aegis/.venv/bin/aegis-mcp",
      "env": { "AEGIS_HOME": "/opt/aegis" }
    }
  }
}
```

Or, project-scoped, drop a `.mcp.json` at the repo root with the same shape.

## Codex CLI / Codex Desktop (OpenAI)

Codex CLI reads MCP servers from `~/.codex/mcp.json`:

```json
{
  "servers": {
    "aegis": {
      "command": "/opt/aegis/.venv/bin/aegis-mcp",
      "transport": "stdio",
      "env": { "AEGIS_HOME": "/opt/aegis" }
    }
  }
}
```

Codex Desktop uses the same shape under Settings > MCP servers.

## Cursor / Continue / Zed

These clients accept the same generic stdio shape:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/opt/aegis/.venv/bin/aegis-mcp",
      "env": { "AEGIS_HOME": "/opt/aegis" }
    }
  }
}
```

## Verifying the connection

After restarting the client, ask the model:

> Use the show_charter tool from aegis.

You should see the charter fingerprint and the list of hard rules. Then try:

> Run scan_path against /path/to/some/repo and report critical findings.

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
