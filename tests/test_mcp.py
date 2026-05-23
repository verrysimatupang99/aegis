"""Tests for the MCP stdio server using direct dispatch (no subprocess)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.mcp.server import AegisMCP


REPO = Path(__file__).resolve().parents[1]


@pytest.fixture()
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AegisMCP:
    monkeypatch.chdir(REPO)
    monkeypatch.setenv("AEGIS_HOME", str(REPO))
    return AegisMCP(
        charter_path=REPO / "data" / "mythos.yaml",
        index_path=tmp_path / "idx.sqlite",
    )


def test_initialize(server: AegisMCP) -> None:
    resp = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert resp is not None
    assert resp["result"]["serverInfo"]["name"] == "aegis"
    assert "tools" in resp["result"]["capabilities"]


def test_tools_list_contains_core_tools(server: AegisMCP) -> None:
    resp = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert resp is not None
    names = {t["name"] for t in resp["result"]["tools"]}
    assert {"scan_path", "report_findings", "show_charter", "tail_journal", "explain_finding"} <= names


def test_show_charter_tool_returns_fingerprint(server: AegisMCP) -> None:
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "show_charter", "arguments": {}},
        }
    )
    assert resp is not None
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["fingerprint"]
    assert payload["identity"]["name"]


def test_scan_then_report_through_mcp(server: AegisMCP, tmp_path: Path) -> None:
    sample = tmp_path / "sample.env"
    sample.write_text("OPENAI_KEY=sk-" + "Z" * 40 + "\n", encoding="utf-8")

    scan = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "scan_path", "arguments": {"path": str(tmp_path)}},
        }
    )
    assert scan is not None
    body = json.loads(scan["result"]["content"][0]["text"])
    assert body["files_indexed"] >= 1
    assert body["findings_added"] >= 1

    rep = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "report_findings",
                "arguments": {"scanner": "secrets"},
            },
        }
    )
    assert rep is not None
    rows = json.loads(rep["result"]["content"][0]["text"])
    assert rows
    assert all(r["scanner"] == "secrets" for r in rows)
    assert all("sk-" not in (r.get("details", {}) or {}).get("redacted", "") for r in rows)


def test_resources_charter_read(server: AegisMCP) -> None:
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "resources/read",
            "params": {"uri": "aegis://charter"},
        }
    )
    assert resp is not None
    contents = resp["result"]["contents"][0]
    assert contents["mimeType"] == "text/yaml"
    assert "version: 1" in contents["text"]


def test_unknown_method_errors_cleanly(server: AegisMCP) -> None:
    resp = server.handle({"jsonrpc": "2.0", "id": 7, "method": "totally/made-up", "params": {}})
    assert resp is not None
    assert "error" in resp
    assert resp["error"]["code"] == -32601
