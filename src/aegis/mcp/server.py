"""Aegis MCP server.

Exposes Aegis tools over the Model Context Protocol so any MCP-aware client
(Claude Desktop, Claude Code, Codex CLI, Cursor, Continue, etc.) can call them
through stdio. The server is a thin wrapper that funnels every tool call
through the same policy engine the CLI uses, so the constitution applies
identically regardless of caller.

Transport: JSON-RPC 2.0 over stdio (line-delimited).

Implements the subset of MCP needed by current clients:
  - initialize / initialized
  - tools/list
  - tools/call
  - resources/list, resources/read
  - logging/setLevel (no-op acknowledged)
  - ping
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

from ..core.constitution import default_path, load
from ..core.index import Index
from ..core.journal import Journal
from ..core.policy import PolicyDenied, PolicyEngine
from ..core.runner import run_scan


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "aegis"
SERVER_VERSION = "0.1.0"


def _project_root() -> Path:
    env = os.environ.get("AEGIS_HOME")
    if env:
        return Path(env).resolve()
    return Path.cwd().resolve()


class AegisMCP:
    def __init__(self, charter_path: Path | None = None, index_path: Path | None = None) -> None:
        self.charter_path = charter_path or default_path(_project_root())
        self.charter = load(self.charter_path)
        self.journal = Journal(
            root=_project_root() / self.charter.journal_path,
            rotate_bytes=self.charter.journal_rotate_mb * 1024 * 1024,
        )
        self.policy = PolicyEngine(constitution=self.charter, journal=self.journal)
        self.index = Index(
            db_path=index_path or _project_root() / "data" / "index.sqlite"
        )
        self.initialized = False

    # ---- tool registry --------------------------------------------------
    def tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "scan_path",
                "description": (
                    "Scan a local directory with all defensive scanners "
                    "(secrets, obfuscation, dependencies, filesystem) and "
                    "store findings in the shared index."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute path to scan"},
                        "max_bytes": {
                            "type": "integer",
                            "description": "Per-file size cap in bytes",
                            "default": 8388608,
                        },
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "report_findings",
                "description": "Return findings from the shared index, optionally filtered.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "scanner": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
            {
                "name": "explain_finding",
                "description": (
                    "Return a plain-language explanation for a single finding "
                    "fingerprint, including remediation hints."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "fingerprint": {"type": "string"},
                    },
                    "required": ["fingerprint"],
                },
            },
            {
                "name": "show_charter",
                "description": "Return the active Mythos constitution and its fingerprint.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "tail_journal",
                "description": "Return recent Glasswing journal entries.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "default": 20},
                        "kind": {"type": "string"},
                    },
                },
            },
        ]

    def resources(self) -> list[dict[str, Any]]:
        return [
            {
                "uri": "aegis://charter",
                "name": "Mythos charter",
                "description": "The active Aegis constitution (read-only).",
                "mimeType": "text/yaml",
            },
            {
                "uri": "aegis://index/stats",
                "name": "Index stats",
                "description": "Counts of files and findings in the shared index.",
                "mimeType": "application/json",
            },
        ]

    # ---- tool implementations -------------------------------------------
    def _tool_scan_path(self, args: dict[str, Any]) -> str:
        path = Path(str(args.get("path") or "")).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"path not found: {path}")
        max_bytes = int(args.get("max_bytes") or 8 * 1024 * 1024)
        report = run_scan(root=path, index=self.index, policy=self.policy, max_bytes=max_bytes)
        return json.dumps(
            {
                "files_indexed": report.files_indexed,
                "findings_added": report.findings_added,
                "findings_skipped": report.findings_skipped,
                "by_scanner": report.by_scanner,
                "by_severity": report.by_severity,
                "charter_fp": self.charter.fingerprint,
            },
            indent=2,
        )

    def _tool_report_findings(self, args: dict[str, Any]) -> str:
        severity = args.get("severity")
        scanner = args.get("scanner")
        limit = int(args.get("limit") or 50)
        rows = list(self.index.findings(severity=severity, scanner=scanner))
        rows = rows[:limit]
        return json.dumps(rows, indent=2, default=str)

    def _tool_explain_finding(self, args: dict[str, Any]) -> str:
        fp = str(args.get("fingerprint") or "")
        if not fp:
            raise ValueError("fingerprint required")
        for row in self.index.findings():
            if row["fingerprint"] == fp:
                return json.dumps(
                    {
                        "finding": row,
                        "explanation": self._explain(row),
                    },
                    indent=2,
                    default=str,
                )
        raise LookupError(f"no finding with fingerprint {fp!r}")

    def _tool_show_charter(self, args: dict[str, Any]) -> str:
        return json.dumps(
            {
                "path": str(self.charter.source_path),
                "fingerprint": self.charter.fingerprint,
                "identity": self.charter.identity,
                "hard_rules": [
                    {"id": r.id, "description": r.description}
                    for r in self.charter.hard_rules
                ],
                "soft_rules": [
                    {"id": r.id, "description": r.description}
                    for r in self.charter.soft_rules
                ],
                "network_allowlist": list(self.charter.network_allowlist),
            },
            indent=2,
        )

    def _tool_tail_journal(self, args: dict[str, Any]) -> str:
        limit = int(args.get("limit") or 20)
        kinds = [str(args["kind"])] if args.get("kind") else None
        entries = list(self.journal.replay(kinds=kinds))
        return json.dumps(entries[-limit:], indent=2, default=str)

    def _explain(self, row: dict[str, Any]) -> str:
        rule = row.get("rule")
        scanner = row.get("scanner")
        details = row.get("details") or {}
        templates = {
            ("obfuscation", "obfuscated_loader"): (
                "This file shows multiple signs of being a packer or self-"
                "extracting loader: high entropy, exotic Unicode noise, runtime "
                "eval/Function calls, and sometimes anti-debug or self-extract "
                "patterns. Treat the file as untrusted, do not execute it on a "
                "host you care about, and inspect any decoded payload in a "
                "sandbox."
            ),
            ("secrets", "github_pat"): (
                "A GitHub personal access token was detected. Rotate it now via "
                "GitHub > Settings > Developer settings > Personal access tokens, "
                "then remove it from version control history."
            ),
            ("dependencies", "non_registry_dep"): (
                "This package is installed from a URL or git repository, "
                "bypassing the registry's review pipeline. Pin to a known "
                "commit hash or replace with a registry-published version."
            ),
            ("filesystem", "world_writable"): (
                "A file is world-writable, meaning any local user can modify "
                "it. Tighten permissions with `chmod o-w <path>`."
            ),
        }
        return templates.get(
            (scanner, rule),
            f"Finding {scanner}/{rule}: see details for context. Severity is "
            f"{row.get('severity')}.",
        ) + (f" Details: {json.dumps(details, default=str)}" if details else "")

    # ---- JSON-RPC dispatch ---------------------------------------------
    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = msg.get("method")
        rpc_id = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            self.initialized = True
            return self._ok(
                rpc_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"listChanged": False, "subscribe": False},
                        "logging": {},
                    },
                },
            )
        if method == "initialized" or method == "notifications/initialized":
            return None
        if method == "ping":
            return self._ok(rpc_id, {})
        if method == "logging/setLevel":
            return self._ok(rpc_id, {})
        if method == "tools/list":
            return self._ok(rpc_id, {"tools": self.tools()})
        if method == "resources/list":
            return self._ok(rpc_id, {"resources": self.resources()})
        if method == "resources/read":
            uri = str(params.get("uri") or "")
            if uri == "aegis://charter":
                return self._ok(
                    rpc_id,
                    {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "text/yaml",
                                "text": self.charter.source_path.read_text("utf-8"),
                            }
                        ]
                    },
                )
            if uri == "aegis://index/stats":
                return self._ok(
                    rpc_id,
                    {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(self.index.stats(), indent=2),
                            }
                        ]
                    },
                )
            return self._err(rpc_id, -32602, f"unknown resource {uri!r}")
        if method == "tools/call":
            return self._dispatch_tool(rpc_id, params)
        return self._err(rpc_id, -32601, f"method not found: {method!r}")

    def _dispatch_tool(self, rpc_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        args = params.get("arguments") or {}
        impls: dict[str, Callable[[dict[str, Any]], str]] = {
            "scan_path": self._tool_scan_path,
            "report_findings": self._tool_report_findings,
            "explain_finding": self._tool_explain_finding,
            "show_charter": self._tool_show_charter,
            "tail_journal": self._tool_tail_journal,
        }
        impl = impls.get(str(name))
        if impl is None:
            return self._err(rpc_id, -32602, f"unknown tool {name!r}")
        try:
            text = impl(args)
            return self._ok(
                rpc_id,
                {
                    "content": [{"type": "text", "text": text}],
                    "isError": False,
                },
            )
        except PolicyDenied as exc:
            self.journal.write("mcp.denied", {"tool": name, "rule": exc.rule_id, "reason": exc.message})
            return self._ok(
                rpc_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": f"DENIED by charter rule {exc.rule_id}: {exc.message}",
                        }
                    ],
                    "isError": True,
                },
            )
        except Exception as exc:  # noqa: BLE001
            self.journal.write(
                "mcp.error",
                {"tool": name, "error": str(exc), "trace": traceback.format_exc()[-1500:]},
            )
            return self._ok(
                rpc_id,
                {
                    "content": [{"type": "text", "text": f"ERROR: {exc}"}],
                    "isError": True,
                },
            )

    @staticmethod
    def _ok(rpc_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

    @staticmethod
    def _err(rpc_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def serve_stdio() -> int:
    server = AegisMCP()
    server.journal.write("mcp.start", {"charter_fp": server.charter.fingerprint})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, list):
            for m in msg:
                resp = server.handle(m)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
        else:
            resp = server.handle(msg)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(serve_stdio())
