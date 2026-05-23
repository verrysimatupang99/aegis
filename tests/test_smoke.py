"""End-to-end smoke test using the archived arctryx loader as a known-bad sample.

The trash directory is created by the human operator when they relocate the
original toolkit; if it is missing we skip rather than fail, because the test
is environment-bound.
"""

from __future__ import annotations

import glob
import os
import shutil
from pathlib import Path

import pytest

from aegis.core.constitution import load
from aegis.core.index import Index
from aegis.core.journal import Journal
from aegis.core.policy import PolicyEngine
from aegis.core.runner import run_scan


REPO = Path(__file__).resolve().parents[1]


def _trash() -> Path | None:
    matches = sorted(glob.glob("/tmp/arctryx-trash-*"))
    return Path(matches[-1]) if matches else None


def test_charter_loads_and_is_immutable_in_memory(tmp_path: Path) -> None:
    charter = load(REPO / "data" / "mythos.yaml")
    assert charter.version == 1
    assert any(r.id == "defensive_only" for r in charter.hard_rules)
    assert charter.fingerprint
    with pytest.raises(Exception):
        charter.hard_rules[0].id = "tampered"  # type: ignore[misc]


def test_policy_blocks_unlisted_host(tmp_path: Path) -> None:
    charter = load(REPO / "data" / "mythos.yaml")
    journal = Journal(root=tmp_path / "journal")
    policy = PolicyEngine(constitution=charter, journal=journal)
    from aegis.core.policy import PolicyDenied

    with pytest.raises(PolicyDenied):
        policy.check_action("net.http", {"host": "evil.example.com"})


def test_policy_allows_anthropic_host(tmp_path: Path) -> None:
    charter = load(REPO / "data" / "mythos.yaml")
    journal = Journal(root=tmp_path / "journal")
    policy = PolicyEngine(constitution=charter, journal=journal)
    decision = policy.check_action("llm.call", {"host": "api.anthropic.com"})
    assert decision.allowed


def test_secrets_scanner_redacts(tmp_path: Path) -> None:
    sample = tmp_path / "sample.env"
    sample.write_text(
        "GH_TOKEN=ghp_" + "A" * 40 + "\n"
        "AWS_KEY=AKIA" + "B" * 16 + "\n",
        encoding="utf-8",
    )
    charter = load(REPO / "data" / "mythos.yaml")
    journal = Journal(root=tmp_path / "journal")
    policy = PolicyEngine(constitution=charter, journal=journal)
    index = Index(db_path=tmp_path / "idx.sqlite")
    report = run_scan(root=tmp_path, index=index, policy=policy)
    assert report.findings_added >= 2
    rows = list(index.findings(scanner="secrets"))
    assert rows
    for row in rows:
        details = row["details"]
        assert details["redacted"].startswith("sha256:")
        assert "ghp_" not in details["redacted"]


def test_obfuscation_scanner_flags_arctryx_loader(tmp_path: Path) -> None:
    trash = _trash()
    if trash is None or not (trash / "start").is_file():
        pytest.skip("archived arctryx loader not present")

    bench = tmp_path / "bench"
    bench.mkdir()
    shutil.copy2(trash / "start", bench / "start")

    charter = load(REPO / "data" / "mythos.yaml")
    journal = Journal(root=tmp_path / "journal")
    policy = PolicyEngine(constitution=charter, journal=journal)
    index = Index(db_path=tmp_path / "idx.sqlite")
    report = run_scan(root=bench, index=index, policy=policy, max_bytes=64 * 1024 * 1024)

    obf = [r for r in index.findings(scanner="obfuscation")]
    assert obf, "obfuscation scanner should flag the arctryx loader"
    severities = {r["severity"] for r in obf}
    assert severities & {"critical", "high", "medium"}
