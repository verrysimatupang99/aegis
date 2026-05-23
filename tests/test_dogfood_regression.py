"""Regression tests pulled from dogfooding Aegis on its own source.

When v0.1.0 first scanned the project itself, two false positives surfaced:
  * dockerfile scanner matched 'dockerfile.py' (and any 'dockerfile.<lang>'
    code file) because of an over-broad startswith() check.
  * obfuscation scanner matched the obfuscation scanner's own .py source
    because Python files were treated as JS-family code-like inputs.

These tests pin both fixes so we don't regress as the heuristics evolve.
"""

from __future__ import annotations

from pathlib import Path

from aegis.core.constitution import load
from aegis.core.index import Index
from aegis.core.journal import Journal
from aegis.core.policy import PolicyEngine
from aegis.core.runner import run_scan
from aegis.scanners.dockerfile import _looks_like_dockerfile


REPO = Path(__file__).resolve().parents[1]


def _bootstrap(tmp_path: Path) -> tuple[PolicyEngine, Index]:
    charter = load(REPO / "data" / "mythos.yaml")
    journal = Journal(root=tmp_path / "journal")
    policy = PolicyEngine(constitution=charter, journal=journal)
    index = Index(db_path=tmp_path / "idx.sqlite")
    return policy, index


def test_dockerfile_heuristic_excludes_code_files() -> None:
    assert _looks_like_dockerfile(Path("Dockerfile")) is True
    assert _looks_like_dockerfile(Path("Dockerfile.dev")) is True
    assert _looks_like_dockerfile(Path("dev.dockerfile")) is True
    # Code or doc files that happen to mention 'dockerfile' must be skipped.
    assert _looks_like_dockerfile(Path("dockerfile.py")) is False
    assert _looks_like_dockerfile(Path("dockerfile.md")) is False
    assert _looks_like_dockerfile(Path("dockerfile.json")) is False
    assert _looks_like_dockerfile(Path("scanners/dockerfile.py")) is False


def test_self_scan_produces_no_false_positives(tmp_path: Path) -> None:
    """Aegis scanning its own src/ directory should yield zero findings."""
    policy, index = _bootstrap(tmp_path)
    run_scan(root=REPO / "src", index=index, policy=policy, max_bytes=4 * 1024 * 1024)
    rows = list(index.findings())
    assert rows == [], (
        "Aegis scanned itself and produced false positives: "
        + ", ".join(f"{r['scanner']}/{r['rule']} on {r['path']}" for r in rows)
    )


def test_runner_isolates_misbehaving_scanner(tmp_path: Path) -> None:
    """If one scanner crashes, the others must still run and findings persist."""
    policy, index = _bootstrap(tmp_path)

    class ExplodingScanner:
        name = "exploding"

        def scan(self, ctx):  # noqa: D401, ANN001
            raise RuntimeError("kaboom")

    from aegis.scanners.secrets import SecretsScanner

    sample = tmp_path / "sample.env"
    sample.write_text("OPENAI_KEY=sk-" + "Z" * 40 + "\n", encoding="utf-8")

    run_scan(
        root=tmp_path,
        index=index,
        policy=policy,
        scanners=[ExplodingScanner(), SecretsScanner()],
    )

    rows = list(index.findings(scanner="secrets"))
    assert rows, "secrets scanner findings should still be recorded"
    errors = list(policy.journal.replay(kinds=["scan.scanner_error"]))
    assert any(e["payload"]["scanner"] == "exploding" for e in errors)
