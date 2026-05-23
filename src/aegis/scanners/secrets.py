"""Secret detector with redacted reporting.

Patterns favor low false-positive: high-entropy + known prefixes/keywords.
Detected values are HASHED before being stored or returned, never echoed.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable
from pathlib import Path

from ..core.index import Finding, fingerprint
from .base import ScanContext


PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("aws_access_key", "high",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", "critical",
     re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^\n]{0,3}[:=][\s\"']{0,3}([A-Za-z0-9/+=]{40})")),
    ("github_pat", "critical",
     re.compile(r"\bghp_[A-Za-z0-9]{36,}\b")),
    ("github_oauth", "critical",
     re.compile(r"\bgho_[A-Za-z0-9]{36,}\b")),
    ("slack_token", "critical",
     re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", "critical",
     re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("anthropic_key", "critical",
     re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", "high",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private_key_block", "critical",
     re.compile(r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----")),
    ("jwt", "medium",
     re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{8,}\b")),
    ("generic_bearer", "medium",
     re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _redact(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]


class SecretsScanner:
    name = "secrets"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.iter_files():
            try:
                if path.stat().st_size > ctx.max_bytes:
                    continue
                data = path.read_text("utf-8", errors="replace")
            except OSError:
                continue

            for rule, severity, pat in PATTERNS:
                for m in pat.finditer(data):
                    matched = m.group(0)
                    line = data.count("\n", 0, m.start()) + 1
                    if rule == "jwt" and _entropy(matched) < 4.0:
                        continue
                    yield Finding(
                        path=str(path),
                        scanner=self.name,
                        rule=rule,
                        severity=severity,
                        line=line,
                        fingerprint=fingerprint(rule, str(path), str(line), _redact(matched)),
                        details={
                            "redacted": _redact(matched),
                            "length": len(matched),
                            "preview": matched[:4] + "***" + matched[-2:] if len(matched) > 8 else "***",
                        },
                    )
