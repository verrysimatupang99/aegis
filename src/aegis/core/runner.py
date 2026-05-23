"""Scan runner: orchestrates scanners through the policy gate and writes the
shared index + journal. The single entry point used by both the CLI and tests.
"""

from __future__ import annotations

import dataclasses
import hashlib
import mimetypes
from collections.abc import Iterable
from pathlib import Path

from ..scanners.base import ScanContext, Scanner
from ..scanners.dependencies import DependencyScanner
from ..scanners.dockerfile import DockerfileScanner
from ..scanners.filesystem import FilesystemScanner
from ..scanners.iac import IacScanner
from ..scanners.obfuscation import ObfuscationScanner
from ..scanners.secrets import SecretsScanner
from .index import Index
from .policy import PolicyEngine


def all_scanners(*, with_yara: bool = True) -> list[Scanner]:
    scanners: list[Scanner] = [
        SecretsScanner(),
        ObfuscationScanner(),
        DependencyScanner(),
        FilesystemScanner(),
        DockerfileScanner(),
        IacScanner(),
    ]
    if with_yara:
        try:
            from ..scanners.yara_rules import YaraScanner

            scanner = YaraScanner()
            if scanner._rules is not None:
                scanners.append(scanner)
        except Exception:  # noqa: BLE001
            pass
    return scanners


@dataclasses.dataclass
class ScanReport:
    files_indexed: int
    findings_added: int
    findings_skipped: int
    by_scanner: dict[str, int]
    by_severity: dict[str, int]


def _hash_file(path: Path) -> tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


def run_scan(
    root: Path,
    index: Index,
    policy: PolicyEngine,
    scanners: Iterable[Scanner] | None = None,
    max_bytes: int = 8 * 1024 * 1024,
    extra_excluded_dirs: tuple[str, ...] = (),
) -> ScanReport:
    root = root.resolve()
    policy.check_action("scan.start", {"root": str(root), "extra_excluded": list(extra_excluded_dirs)})
    base_excluded = ScanContext.__dataclass_fields__["excluded_dirs"].default
    merged = tuple(dict.fromkeys(base_excluded + tuple(extra_excluded_dirs)))
    ctx = ScanContext(root=root, max_bytes=max_bytes, excluded_dirs=merged)

    # We deliberately do NOT call policy.check_action() per file. Whole-
    # workspace scans index tens of thousands of files; each policy call
    # writes a JSON line to the journal, which is the dominant cost. We
    # journal one 'fs.read.batch' summary at the end instead.
    files = 0
    read_errors = 0
    for path in ctx.iter_files():
        try:
            size, sha = _hash_file(path)
            mime, _ = mimetypes.guess_type(path.name)
            index.upsert_file(str(path), size, sha, path.stat().st_mtime, mime)
            files += 1
        except OSError:
            read_errors += 1
            continue
    policy.journal.write(
        "fs.read.batch",
        {"root": str(root), "files_indexed": files, "read_errors": read_errors},
    )

    added = 0
    skipped = 0
    by_scanner: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for scanner in scanners or all_scanners():
        try:
            scanner_findings = list(scanner.scan(ctx))
        except Exception as exc:  # noqa: BLE001
            policy.journal.write(
                "scan.scanner_error",
                {
                    "scanner": getattr(scanner, "name", scanner.__class__.__name__),
                    "error": str(exc),
                },
            )
            continue
        for finding in scanner_findings:
            if index.add_finding(finding):
                added += 1
                by_scanner[finding.scanner] = by_scanner.get(finding.scanner, 0) + 1
                by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
                policy.journal.write(
                    "scan.finding",
                    {
                        "scanner": finding.scanner,
                        "rule": finding.rule,
                        "severity": finding.severity,
                        "path": finding.path,
                        "fingerprint": finding.fingerprint,
                        "line": finding.line,
                        "details": finding.details,
                    },
                )
            else:
                skipped += 1

    report = ScanReport(
        files_indexed=files,
        findings_added=added,
        findings_skipped=skipped,
        by_scanner=by_scanner,
        by_severity=by_severity,
    )
    policy.journal.write(
        "scan.complete",
        {
            "root": str(root),
            "files": report.files_indexed,
            "added": report.findings_added,
            "skipped": report.findings_skipped,
            "by_scanner": report.by_scanner,
            "by_severity": report.by_severity,
        },
    )
    return report
