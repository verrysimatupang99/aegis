"""Tests for the Dockerfile and IaC scanners."""

from __future__ import annotations

from pathlib import Path

from aegis.core.constitution import load
from aegis.core.index import Index
from aegis.core.journal import Journal
from aegis.core.policy import PolicyEngine
from aegis.core.runner import run_scan


REPO = Path(__file__).resolve().parents[1]


def _bootstrap(tmp_path: Path) -> tuple[PolicyEngine, Index]:
    charter = load(REPO / "data" / "mythos.yaml")
    journal = Journal(root=tmp_path / "journal")
    policy = PolicyEngine(constitution=charter, journal=journal)
    index = Index(db_path=tmp_path / "idx.sqlite")
    return policy, index


def test_dockerfile_finds_root_latest_envsecret_curlsh(tmp_path: Path) -> None:
    bench = tmp_path / "bench"
    bench.mkdir()
    (bench / "Dockerfile").write_text(
        "FROM python\n"
        "ENV API_KEY=hardcoded-token-123456\n"
        "RUN curl https://example.com/install.sh | sh\n"
        "RUN chmod -R 777 /app\n"
        "ADD https://example.com/x.tar.gz /app/\n",
        encoding="utf-8",
    )
    policy, index = _bootstrap(tmp_path)
    run_scan(root=bench, index=index, policy=policy)
    rules = {r["rule"] for r in index.findings(scanner="dockerfile")}
    assert {"runs_as_root", "from_latest_or_untagged", "credential_in_env_or_arg",
            "curl_pipe_sh", "chmod_777", "add_remote_url"} <= rules


def test_dockerfile_clean_passes(tmp_path: Path) -> None:
    bench = tmp_path / "bench"
    bench.mkdir()
    (bench / "Dockerfile").write_text(
        "FROM python:3.12.5-slim AS app\n"
        "RUN useradd -u 1000 app\n"
        "USER app\n"
        "COPY --chown=app:app . /app\n",
        encoding="utf-8",
    )
    policy, index = _bootstrap(tmp_path)
    run_scan(root=bench, index=index, policy=policy)
    rows = list(index.findings(scanner="dockerfile"))
    assert rows == []


def test_iac_terraform_flags_public_s3_open_cidr_literal_secret(tmp_path: Path) -> None:
    bench = tmp_path / "bench"
    bench.mkdir()
    (bench / "main.tf").write_text(
        'resource "aws_s3_bucket_acl" "x" {\n'
        '  acl = "public-read"\n'
        '}\n'
        'resource "aws_security_group_rule" "y" {\n'
        '  type = "ingress"\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n'
        '}\n'
        'resource "aws_db_instance" "z" {\n'
        '  password = "supersecret-literal-1234"\n'
        '}\n',
        encoding="utf-8",
    )
    policy, index = _bootstrap(tmp_path)
    run_scan(root=bench, index=index, policy=policy)
    rules = {r["rule"] for r in index.findings(scanner="iac")}
    assert {"tf_s3_public_acl", "tf_open_security_group", "tf_literal_secret"} <= rules


def test_iac_gha_flags_unpinned_uses_and_curl_sh(tmp_path: Path) -> None:
    wf = tmp_path / "bench" / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on:\n"
        "  pull_request_target: {}\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: curl https://x | sh\n",
        encoding="utf-8",
    )
    policy, index = _bootstrap(tmp_path)
    run_scan(root=tmp_path / "bench", index=index, policy=policy)
    rules = {r["rule"] for r in index.findings(scanner="iac")}
    assert "gha_uses_unpinned" in rules
    assert "gha_curl_pipe_sh" in rules
    assert "gha_pull_request_target" in rules


def test_iac_gha_pinned_sha_passes(tmp_path: Path) -> None:
    wf = tmp_path / "bench" / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675\n",
        encoding="utf-8",
    )
    policy, index = _bootstrap(tmp_path)
    run_scan(root=tmp_path / "bench", index=index, policy=policy)
    rules = {r["rule"] for r in index.findings(scanner="iac")}
    assert "gha_uses_unpinned" not in rules
