"""Tests for the --exclude flag and additional default excluded dirs."""

from __future__ import annotations

from pathlib import Path

from aegis.core.constitution import load
from aegis.core.index import Index
from aegis.core.journal import Journal
from aegis.core.policy import PolicyEngine
from aegis.core.runner import run_scan
from aegis.scanners.base import ScanContext


REPO = Path(__file__).resolve().parents[1]


def test_default_excludes_include_common_build_dirs() -> None:
    defaults = ScanContext.__dataclass_fields__["excluded_dirs"].default
    for name in ("target", ".next", "vendor", ".cache", ".pytest_cache",
                 ".mypy_cache", ".ruff_cache", "site-packages",
                 "gen", "artifacts", "models"):
        assert name in defaults, f"expected {name!r} in default excluded_dirs"


def test_extra_excluded_dirs_skip_matching_path_components(tmp_path: Path) -> None:
    bench = tmp_path / "bench"
    (bench / "src").mkdir(parents=True)
    (bench / "junkdir").mkdir()
    (bench / "src" / "leak.env").write_text(
        "GH_TOKEN=ghp_" + "A" * 40 + "\n", encoding="utf-8"
    )
    (bench / "junkdir" / "also_leak.env").write_text(
        "GH_TOKEN=ghp_" + "B" * 40 + "\n", encoding="utf-8"
    )

    charter = load(REPO / "data" / "mythos.yaml")
    journal = Journal(root=tmp_path / "journal")
    policy = PolicyEngine(constitution=charter, journal=journal)
    index = Index(db_path=tmp_path / "idx.sqlite")

    run_scan(
        root=bench,
        index=index,
        policy=policy,
        extra_excluded_dirs=("junkdir",),
    )
    paths = {row["path"] for row in index.findings(scanner="secrets")}
    assert any(p.endswith("src/leak.env") for p in paths)
    assert not any("junkdir" in p for p in paths), (
        f"junkdir should have been skipped; got {paths!r}"
    )
