"""Aegis CLI entry point.

Subcommands:
  scan <path>       run all scanners, write findings to the shared index
  report            print a digest of the latest findings
  report --html OUT export a static HTML report
  journal           tail the Glasswing journal
  charter           print the active Mythos constitution + fingerprint
  serve mcp         run the MCP stdio server for Claude/Codex/etc.
  advise            ask the LLM (cloud or local) for plain-language guidance
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..core.constitution import Constitution, ConstitutionError, default_path, load
from ..core.index import Index
from ..core.journal import Journal
from ..core.policy import PolicyEngine
from ..core.runner import run_scan


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _bootstrap(args: argparse.Namespace) -> tuple[Constitution, Journal, PolicyEngine, Index]:
    charter_path = Path(args.charter) if args.charter else default_path()
    charter = load(charter_path)
    journal_root = Path.cwd() / charter.journal_path
    journal = Journal(root=journal_root, rotate_bytes=charter.journal_rotate_mb * 1024 * 1024)
    policy = PolicyEngine(
        constitution=charter,
        journal=journal,
        allow_exfil=tuple(args.allow_exfil or ()),
        i_mean_it=bool(args.i_mean_it),
    )
    index_path = Path(args.index) if args.index else Path.cwd() / "data" / "index.sqlite"
    index = Index(db_path=index_path)
    journal.write(
        "session.start",
        {
            "charter": str(charter.source_path),
            "charter_fp": charter.fingerprint,
            "subcommand": args.cmd,
        },
    )
    return charter, journal, policy, index


def cmd_scan(args: argparse.Namespace) -> int:
    charter, journal, policy, index = _bootstrap(args)
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"aegis: path not found: {root}", file=sys.stderr)
        return 2
    extras = tuple(args.exclude or ())
    report = run_scan(
        root=root,
        index=index,
        policy=policy,
        max_bytes=args.max_bytes,
        extra_excluded_dirs=extras,
    )
    print(f"Aegis charter: {charter.identity.get('name','Aegis')} ({charter.fingerprint})")
    print(f"Indexed {report.files_indexed} files")
    print(f"Findings added: {report.findings_added} (skipped dupes: {report.findings_skipped})")
    if report.by_severity:
        bits = [f"{sev}={report.by_severity.get(sev,0)}" for sev in SEVERITY_ORDER if sev in report.by_severity]
        print("By severity: " + ", ".join(bits))
    if report.by_scanner:
        print("By scanner: " + ", ".join(f"{k}={v}" for k, v in sorted(report.by_scanner.items())))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    charter, journal, policy, index = _bootstrap(args)
    if args.html:
        from ..intel.report_html import render

        out = render(index, Path(args.html))
        print(f"wrote {out}")
        return 0
    rows = list(index.findings(severity=args.severity, scanner=args.scanner))
    if not rows:
        print("(no findings)")
        return 0
    if args.format == "json":
        json.dump(rows, sys.stdout, indent=2, default=str)
        print()
        return 0
    rows.sort(
        key=lambda r: (
            SEVERITY_ORDER.index(r["severity"]) if r["severity"] in SEVERITY_ORDER else 99,
            r["path"],
        )
    )
    for r in rows[: args.limit]:
        loc = f":{r['line']}" if r.get("line") else ""
        print(f"[{r['severity']:8}] {r['scanner']}/{r['rule']}  {r['path']}{loc}")
        for k, v in (r.get("details") or {}).items():
            print(f"    {k}: {v}")
    print(f"-- {len(rows)} findings total --")
    return 0


def cmd_charter(args: argparse.Namespace) -> int:
    charter, *_ = _bootstrap(args)
    print(f"Charter: {charter.source_path}")
    print(f"Fingerprint: {charter.fingerprint}")
    print(f"Identity: {charter.identity.get('name')} - {charter.identity.get('role')}")
    print(f"Hard rules ({len(charter.hard_rules)}):")
    for r in charter.hard_rules:
        print(f"  - {r.id}")
    print(f"Soft rules ({len(charter.soft_rules)}):")
    for r in charter.soft_rules:
        print(f"  - {r.id}")
    print(f"Network allowlist: {', '.join(charter.network_allowlist) or '(empty)'}")
    return 0


def cmd_journal(args: argparse.Namespace) -> int:
    charter, journal, policy, index = _bootstrap(args)
    entries = list(journal.replay(kinds=args.kind or None))
    entries = entries[-args.limit:]
    for rec in entries:
        kind = rec.get("kind")
        ts = rec.get("iso") or rec.get("ts")
        payload = rec.get("payload", {})
        print(f"{ts} [{kind}]")
        for k, v in payload.items():
            print(f"  {k}: {v}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    if args.transport != "mcp":
        print(f"unknown transport {args.transport!r}", file=sys.stderr)
        return 2
    from ..mcp.server import serve_stdio

    return serve_stdio()


def cmd_advise(args: argparse.Namespace) -> int:
    charter, journal, policy, index = _bootstrap(args)
    rows = list(index.findings(severity=args.severity, scanner=args.scanner))[: args.limit]
    if not rows:
        print("(no findings to advise on)")
        return 0
    redacted = [
        {
            "scanner": r["scanner"],
            "rule": r["rule"],
            "severity": r["severity"],
            "path": r["path"],
            "details": r["details"],
        }
        for r in rows
    ]
    user = (
        "You are reviewing the following Aegis findings. For each, give a "
        "1-2 sentence remediation suggestion in plain English. Do not propose "
        "exploitation steps; defensive guidance only.\n\n"
        + json.dumps(redacted, indent=2, default=str)
    )
    system = charter.identity.get("persona") or "You are Aegis, a defensive security copilot."

    if args.local:
        from ..intel.local_llm import LocalLLM, LocalLLMUnavailable

        llm = LocalLLM(policy=policy, model=args.model or "llama3.1")
        try:
            resp = llm.advise(system=system, user=user)
        except LocalLLMUnavailable as exc:
            print(f"local LLM unavailable: {exc}", file=sys.stderr)
            return 4
        print(f"[{resp.model} @ {resp.host}]\n{resp.text}")
        return 0

    from ..core.llm import LLM, LLMUnavailable

    llm = LLM(policy=policy, model=args.model or "claude-3-5-sonnet-latest")
    try:
        resp = llm.advise(system=system, user=user)
    except LLMUnavailable as exc:
        print(f"cloud LLM unavailable: {exc}", file=sys.stderr)
        return 4
    print(f"[{resp.model}]\n{resp.text}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="Aegis defensive security copilot")
    p.add_argument("--charter", help="path to mythos.yaml (defaults to project data/mythos.yaml)")
    p.add_argument("--index", help="path to shared index sqlite")
    p.add_argument("--allow-exfil", action="append", help="explicitly allow outbound host")
    p.add_argument("--i-mean-it", action="store_true", help="acknowledge destructive actions")

    sub = p.add_subparsers(dest="cmd", required=True)

    s_scan = sub.add_parser("scan", help="scan a directory")
    s_scan.add_argument("path", help="directory to scan")
    s_scan.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024)
    s_scan.add_argument(
        "--exclude",
        action="append",
        help="directory name to skip (matched against any path component); repeatable",
    )
    s_scan.set_defaults(func=cmd_scan)

    s_report = sub.add_parser("report", help="report findings from the shared index")
    s_report.add_argument("--severity", choices=SEVERITY_ORDER)
    s_report.add_argument("--scanner")
    s_report.add_argument("--limit", type=int, default=50)
    s_report.add_argument("--format", choices=("text", "json"), default="text")
    s_report.add_argument("--html", help="write a static HTML report to this path")
    s_report.set_defaults(func=cmd_report)

    s_charter = sub.add_parser("charter", help="show active constitution")
    s_charter.set_defaults(func=cmd_charter)

    s_journal = sub.add_parser("journal", help="tail the Glasswing journal")
    s_journal.add_argument("--kind", action="append")
    s_journal.add_argument("--limit", type=int, default=20)
    s_journal.set_defaults(func=cmd_journal)

    s_serve = sub.add_parser("serve", help="run a long-lived endpoint (MCP, ...)")
    s_serve.add_argument("transport", choices=("mcp",), help="transport to start")
    s_serve.set_defaults(func=cmd_serve)

    s_advise = sub.add_parser("advise", help="ask LLM (cloud or local) for guidance on findings")
    s_advise.add_argument("--severity", choices=SEVERITY_ORDER)
    s_advise.add_argument("--scanner")
    s_advise.add_argument("--limit", type=int, default=10)
    s_advise.add_argument("--local", action="store_true", help="use local Ollama")
    s_advise.add_argument("--model", help="model name override")
    s_advise.set_defaults(func=cmd_advise)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ConstitutionError as exc:
        print(f"aegis: constitution error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
