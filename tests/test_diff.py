"""Tests for the differential gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.cli.diff import diff, main as diff_main
from aegis.core.index import Finding, Index


def _seed(index: Index, findings: list[Finding]) -> None:
    for f in findings:
        index.add_finding(f)


def test_diff_added_and_removed(tmp_path: Path) -> None:
    base = Index(db_path=tmp_path / "base.sqlite")
    cur = Index(db_path=tmp_path / "cur.sqlite")
    _seed(
        base,
        [
            Finding(path="a.py", scanner="secrets", rule="github_pat", severity="high",
                    line=1, fingerprint="aa", details={}),
            Finding(path="b.py", scanner="secrets", rule="aws_access_key", severity="high",
                    line=1, fingerprint="bb", details={}),
        ],
    )
    _seed(
        cur,
        [
            Finding(path="a.py", scanner="secrets", rule="github_pat", severity="high",
                    line=1, fingerprint="aa", details={}),
            Finding(path="c.py", scanner="obfuscation", rule="obfuscated_loader",
                    severity="critical", line=None, fingerprint="cc", details={}),
        ],
    )
    from aegis.cli.diff import _load_findings

    base_map = _load_findings(tmp_path / "base.sqlite")
    cur_map = _load_findings(tmp_path / "cur.sqlite")
    result = diff(base_map, cur_map)
    assert len(result["added"]) == 1
    assert result["added"][0]["fingerprint"] == "cc"
    assert len(result["removed"]) == 1
    assert result["removed"][0]["fingerprint"] == "bb"
    assert result["severity_changed"] == []


def test_diff_severity_change(tmp_path: Path) -> None:
    base = Index(db_path=tmp_path / "base.sqlite")
    cur = Index(db_path=tmp_path / "cur.sqlite")
    _seed(
        base,
        [Finding(path="x.py", scanner="filesystem", rule="world_writable",
                 severity="medium", line=None, fingerprint="xx", details={})],
    )
    _seed(
        cur,
        [Finding(path="x.py", scanner="filesystem", rule="world_writable",
                 severity="high", line=None, fingerprint="xx", details={})],
    )
    from aegis.cli.diff import _load_findings

    result = diff(_load_findings(tmp_path / "base.sqlite"), _load_findings(tmp_path / "cur.sqlite"))
    assert result["added"] == []
    assert result["removed"] == []
    assert len(result["severity_changed"]) == 1
    assert result["severity_changed"][0]["from"] == "medium"
    assert result["severity_changed"][0]["to"] == "high"


def test_diff_gate_fails_on_new_high(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = Index(db_path=tmp_path / "base.sqlite")
    cur = Index(db_path=tmp_path / "cur.sqlite")
    _seed(
        cur,
        [Finding(path="a.py", scanner="secrets", rule="github_pat", severity="critical",
                 line=1, fingerprint="aa", details={})],
    )
    rc = diff_main([str(tmp_path / "base.sqlite"), str(tmp_path / "cur.sqlite"),
                    "--fail-on", "critical,high"])
    assert rc == 1
    out = capsys.readouterr()
    assert "GATE FAIL" in out.err


def test_diff_gate_passes_when_only_low_added(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    Index(db_path=tmp_path / "base.sqlite")
    cur = Index(db_path=tmp_path / "cur.sqlite")
    _seed(
        cur,
        [Finding(path="a.py", scanner="dependencies", rule="floating_version",
                 severity="low", line=None, fingerprint="aa", details={})],
    )
    rc = diff_main([str(tmp_path / "base.sqlite"), str(tmp_path / "cur.sqlite"),
                    "--fail-on", "critical,high"])
    assert rc == 0
    out = capsys.readouterr()
    assert "GATE PASS" in out.out
