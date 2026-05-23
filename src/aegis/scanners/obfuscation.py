"""Obfuscated / packed JavaScript & shell payload detector.

Heuristics target the patterns we observed in the arctryx `start` loader:
- single-line files with extreme entropy
- heavy use of eval / Function() / Buffer.from / atob / zlib decompress
- exotic Unicode noise (CJK, cuneiform, arrow ranges) in code files
- runtime self-write to `.tmp_*.js` then `unlinkSync`
- anti-debug hooks against process.execArgv / NODE_OPTIONS

Findings are advisory: they tell the user "this file behaves like a packer";
the user decides whether to dig further or quarantine.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from pathlib import Path

from ..core.index import Finding, fingerprint
from .base import ScanContext


# This scanner targets JS-family packers/loaders. Python and shell scripts
# legitimately contain tokens like 'eval(' or 'gunzipSync' as data (e.g. this
# very scanner's source) so they are intentionally excluded.
CODE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts"}

DANGER_TOKENS = (
    "eval(", "new Function(", "Function(", "Buffer.from(", "atob(", "btoa(",
    "createDecipheriv", "gunzipSync", "inflateSync", "brotliDecompressSync",
    "child_process", "spawnSync", "execSync",
    "process.execArgv", "NODE_OPTIONS",
    "writeFileSync", "unlinkSync", "Module._compile",
)

EXOTIC_RANGES = (
    (0x3400, 0x9FFF),    # CJK
    (0x12000, 0x123FF),  # Cuneiform
    (0xA000, 0xA4CF),    # Yi syllables
    (0x2600, 0x27BF),    # misc symbols / dingbats
    (0x2190, 0x21FF),    # arrows
)

SINGLE_LINE_BYTES = 50_000
LONG_LINE_BYTES = 5_000


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _exotic_ratio(s: str) -> float:
    if not s:
        return 0.0
    hits = 0
    for ch in s:
        cp = ord(ch)
        for lo, hi in EXOTIC_RANGES:
            if lo <= cp <= hi:
                hits += 1
                break
    return hits / len(s)


class ObfuscationScanner:
    name = "obfuscation"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.iter_files():
            yield from self._scan_one(path, ctx)

    def _scan_one(self, path: Path, ctx: ScanContext) -> Iterable[Finding]:
        try:
            stat = path.stat()
            if stat.st_size > ctx.max_bytes * 4:
                return
            data = path.read_text("utf-8", errors="replace")
        except OSError:
            return

        suffix = path.suffix.lower()
        treat_as_code = suffix in CODE_SUFFIXES or path.name in {"start", "loader", "init"}
        if not treat_as_code:
            return

        signals: list[str] = []
        details: dict[str, object] = {"size": stat.st_size}

        lines = data.split("\n")
        longest = max((len(line) for line in lines), default=0)
        if stat.st_size > SINGLE_LINE_BYTES and longest > stat.st_size * 0.6:
            signals.append("single_long_line")
            details["longest_line"] = longest
        elif longest > LONG_LINE_BYTES:
            signals.append("long_line")
            details["longest_line"] = longest

        token_hits = {tok: data.count(tok) for tok in DANGER_TOKENS if tok in data}
        if token_hits:
            details["tokens"] = token_hits
            heavy = sum(token_hits.values())
            if heavy >= 4:
                signals.append("danger_tokens")

        exotic = _exotic_ratio(data[:200_000])
        if exotic > 0.05:
            signals.append("exotic_unicode")
            details["exotic_ratio"] = round(exotic, 4)

        sample = data[:200_000]
        ent = _shannon(sample)
        details["entropy"] = round(ent, 3)
        if ent > 5.5 and longest > LONG_LINE_BYTES:
            signals.append("high_entropy")

        tmp_pattern = re.search(r"\.tmp_\$\{.*?\}\.js", data)
        write_unlink_pair = ("writeFileSync" in data) and ("unlinkSync" in data)
        if tmp_pattern or write_unlink_pair:
            signals.append("self_extract")

        if "process.execArgv" in data and ("inspect" in data or "NODE_OPTIONS" in data):
            signals.append("anti_debug")

        if not signals:
            return

        severity = "low"
        weight = len(signals) + (1 if "self_extract" in signals else 0)
        if weight >= 4:
            severity = "critical"
        elif weight >= 3:
            severity = "high"
        elif weight >= 2:
            severity = "medium"

        details["signals"] = signals
        yield Finding(
            path=str(path),
            scanner=self.name,
            rule="obfuscated_loader",
            severity=severity,
            line=None,
            fingerprint=fingerprint(self.name, str(path), ",".join(sorted(signals))),
            details=details,
        )