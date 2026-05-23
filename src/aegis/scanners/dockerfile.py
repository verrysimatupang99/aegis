"""Dockerfile hardening checks.

Heuristic, deliberately conservative. Targets common production smells:
- running as root (no USER directive, or USER root)
- :latest tags or no tag at all in FROM
- ADD with a remote URL (use COPY + curl in a controlled step instead)
- curl|sh / wget|sh pipelines
- secrets baked in via ENV / ARG with credential-shaped names
- chmod 777 / chmod -R 777
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from ..core.index import Finding, fingerprint
from .base import ScanContext


SECRET_LIKE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|aws[_-]?secret|private[_-]?key)"
)
LATEST_OR_NO_TAG = re.compile(r"^FROM\s+(?P<image>\S+)(?:\s+AS\s+\S+)?\s*$", re.IGNORECASE | re.MULTILINE)
ADD_REMOTE = re.compile(r"^\s*ADD\s+https?://", re.IGNORECASE | re.MULTILINE)
CURL_PIPE_SH = re.compile(r"(curl|wget)[^\n]*\|\s*(ba)?sh", re.IGNORECASE)
CHMOD_777 = re.compile(r"chmod\s+(-R\s+)?0?777")


CODE_SUFFIXES_NOT_DOCKERFILE = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".rb", ".php", ".cs",
    ".c", ".cpp", ".h", ".hpp", ".swift", ".kt", ".scala",
    ".md", ".rst", ".txt", ".yaml", ".yml", ".json", ".toml", ".ini",
}


def _looks_like_dockerfile(path: Path) -> bool:
    """Return True only for files that conventionally are Dockerfiles.

    Dockerfile, Dockerfile.dev, dev.dockerfile -> True
    dockerfile.py / dockerfile.md / dockerfile.json -> False (those are source
    code or docs about Dockerfiles, not the build files themselves).
    """
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in CODE_SUFFIXES_NOT_DOCKERFILE:
        return False
    if name == "dockerfile":
        return True
    if suffix == ".dockerfile":
        return True
    # 'Dockerfile.<variant>' convention: variant must be short and alpha only,
    # not a code-file extension.
    if name.startswith("dockerfile."):
        variant = name[len("dockerfile."):]
        return variant.isalpha() and 1 <= len(variant) <= 16
    return False


class DockerfileScanner:
    name = "dockerfile"

    def scan(self, ctx: ScanContext) -> Iterable[Finding]:
        for path in ctx.iter_files():
            if not _looks_like_dockerfile(path):
                continue
            try:
                data = path.read_text("utf-8", errors="replace")
            except OSError:
                continue
            yield from self._check(path, data)

    def _check(self, path: Path, data: str) -> Iterable[Finding]:
        lines = data.splitlines()
        has_user = False
        last_user_root = False
        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            upper = line.upper()
            if upper.startswith("USER "):
                has_user = True
                user_arg = line.split(None, 1)[1].strip()
                last_user_root = user_arg in ("root", "0", "0:0")
            if upper.startswith("FROM "):
                m = LATEST_OR_NO_TAG.match(line)
                if m:
                    image = m.group("image")
                    if ":" not in image or image.endswith(":latest"):
                        yield Finding(
                            path=str(path), scanner=self.name,
                            rule="from_latest_or_untagged",
                            severity="medium", line=i,
                            fingerprint=fingerprint(self.name, "from", str(path), str(i)),
                            details={"image": image},
                        )
            if (upper.startswith("ENV ") or upper.startswith("ARG ")) and SECRET_LIKE.search(line):
                yield Finding(
                    path=str(path), scanner=self.name,
                    rule="credential_in_env_or_arg",
                    severity="high", line=i,
                    fingerprint=fingerprint(self.name, "envarg", str(path), str(i)),
                    details={"snippet": line[:120]},
                )
            if CHMOD_777.search(line):
                yield Finding(
                    path=str(path), scanner=self.name,
                    rule="chmod_777",
                    severity="high", line=i,
                    fingerprint=fingerprint(self.name, "chmod777", str(path), str(i)),
                    details={"snippet": line[:120]},
                )

        for m in ADD_REMOTE.finditer(data):
            line_no = data.count("\n", 0, m.start()) + 1
            yield Finding(
                path=str(path), scanner=self.name,
                rule="add_remote_url",
                severity="medium", line=line_no,
                fingerprint=fingerprint(self.name, "addurl", str(path), str(line_no)),
                details={"hint": "prefer COPY + a separate verified download step"},
            )

        for m in CURL_PIPE_SH.finditer(data):
            line_no = data.count("\n", 0, m.start()) + 1
            yield Finding(
                path=str(path), scanner=self.name,
                rule="curl_pipe_sh",
                severity="high", line=line_no,
                fingerprint=fingerprint(self.name, "curlsh", str(path), str(line_no)),
                details={"hint": "verify a known checksum or pin to a release artifact"},
            )

        if not has_user or last_user_root:
            yield Finding(
                path=str(path), scanner=self.name,
                rule="runs_as_root",
                severity="high", line=None,
                fingerprint=fingerprint(self.name, "rootuser", str(path)),
                details={"reason": "no USER directive, or final USER is root"},
            )
