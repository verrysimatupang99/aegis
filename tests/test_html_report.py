"""Smoke test for HTML report exporter."""

from __future__ import annotations

from pathlib import Path

from aegis.core.constitution import load
from aegis.core.index import Finding, Index
from aegis.core.journal import Journal
from aegis.core.policy import PolicyEngine
from aegis.intel.report_html import render


REPO = Path(__file__).resolve().parents[1]


def test_html_report_renders(tmp_path: Path) -> None:
    index = Index(db_path=tmp_path / "idx.sqlite")
    index.add_finding(
        Finding(
            path=str(tmp_path / "leak.env"),
            scanner="secrets",
            rule="github_pat",
            severity="critical",
            line=1,
            fingerprint="abc123",
            details={"redacted": "sha256:fakeshort", "preview": "ghp_***"},
        )
    )
    out = render(index, tmp_path / "report.html", title="Aegis test report")
    assert out.is_file()
    body = out.read_text("utf-8")
    assert "Aegis test report" in body
    assert "github_pat" in body
    assert "ghp_" not in body or "ghp_***" in body  # only the redacted preview, not raw
    assert "secrets" in body
