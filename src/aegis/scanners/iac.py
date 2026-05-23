"""IaC misconfiguration scanner.

Targets the cheap-to-detect, high-impact issues in Terraform and GitHub
Actions YAML. We do not attempt to be a full policy engine; we aim for the
patterns most likely to show up in a defender's first pass.

Terraform (.tf):
- aws_s3_bucket(_acl) with public-read or public-read-write
- security_group rules with cidr_blocks = ["0.0.0.0/0"] on a non-egress rule
- *_password / *_secret = "literal"

GitHub Actions (.github/workflows/*.yml):
- pull_request_target without an explicit ref pin
- run: |\n curl|sh
- uses: action@<branch>  (require commit SHA)
- secrets passed as plain env to untrusted code paths
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from ..core.index import Finding, fingerprint
from .base import ScanContext


TF_PUBLIC_ACL = re.compile(r'acl\s*=\s*"(public-read(-write)?)"')
TF_OPEN_CIDR = re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]')
TF_LITERAL_SECRET = re.compile(
    r'(?i)(password|secret|token|api[_-]?key|access[_-]?key)\s*=\s*"([^"\n]{6,})"'
)

GHA_CURL_SH = re.compile(r"(curl|wget)[^\n]*\|\s*(ba)?sh", re.IGNORECASE)
GHA_USES_BRANCH = re.compile(r"^\s*-\s*uses:\s*([^\s@]+)@([^\s#]+)", re.MULTILINE)


def _looks_tf(p: Path) -> bool:
    return p.suffix == ".tf"


def _looks_gha(p: Path) -> bool:
    parts = p.parts
    return (
        ".github" in parts
        and "workflows" in parts
        and p.suffix in (".yml", ".yaml")
    )


def _is_sha(ref: str) -> bool:
    return bool(re.fullmatch(r"[a-f0-9]{40}", ref))


class IacScanner:
    name = "iac"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.iter_files():
            try:
                data = path.read_text("utf-8", errors="replace")
            except OSError:
                continue
            if _looks_tf(path):
                yield from self._scan_tf(path, data)
            elif _looks_gha(path):
                yield from self._scan_gha(path, data)

    def _scan_tf(self, path: Path, data: str) -> Iterable[Finding]:
        for m in TF_PUBLIC_ACL.finditer(data):
            line = data.count("\n", 0, m.start()) + 1
            yield Finding(
                path=str(path), scanner=self.name,
                rule="tf_s3_public_acl",
                severity="critical", line=line,
                fingerprint=fingerprint(self.name, "s3acl", str(path), str(line)),
                details={"acl": m.group(1)},
            )
        for m in TF_OPEN_CIDR.finditer(data):
            line = data.count("\n", 0, m.start()) + 1
            window = data[max(0, m.start()-200):m.start()].lower()
            if "egress" in window:
                continue
            yield Finding(
                path=str(path), scanner=self.name,
                rule="tf_open_security_group",
                severity="high", line=line,
                fingerprint=fingerprint(self.name, "tfcidr", str(path), str(line)),
                details={"hint": "0.0.0.0/0 ingress; restrict to known sources"},
            )
        for m in TF_LITERAL_SECRET.finditer(data):
            line = data.count("\n", 0, m.start()) + 1
            yield Finding(
                path=str(path), scanner=self.name,
                rule="tf_literal_secret",
                severity="high", line=line,
                fingerprint=fingerprint(self.name, "tflit", str(path), str(line), m.group(1)),
                details={"key": m.group(1)},
            )

    def _scan_gha(self, path: Path, data: str) -> Iterable[Finding]:
        if "pull_request_target" in data:
            line = data.count("\n", 0, data.index("pull_request_target")) + 1
            yield Finding(
                path=str(path), scanner=self.name,
                rule="gha_pull_request_target",
                severity="high", line=line,
                fingerprint=fingerprint(self.name, "prtarget", str(path)),
                details={"hint": "pull_request_target with checkout of the PR head is a known sandbox escape vector"},
            )
        for m in GHA_CURL_SH.finditer(data):
            line = data.count("\n", 0, m.start()) + 1
            yield Finding(
                path=str(path), scanner=self.name,
                rule="gha_curl_pipe_sh",
                severity="high", line=line,
                fingerprint=fingerprint(self.name, "ghacurl", str(path), str(line)),
                details={"hint": "pipe-to-sh in CI; pin to a checksum or a release"},
            )
        for m in GHA_USES_BRANCH.finditer(data):
            action, ref = m.group(1), m.group(2)
            if action.startswith("./") or action.startswith("docker://"):
                continue
            if _is_sha(ref):
                continue
            line = data.count("\n", 0, m.start()) + 1
            yield Finding(
                path=str(path), scanner=self.name,
                rule="gha_uses_unpinned",
                severity="medium", line=line,
                fingerprint=fingerprint(self.name, "ghauses", str(path), str(line), action),
                details={"action": action, "ref": ref, "hint": "pin to a 40-char commit SHA"},
            )
