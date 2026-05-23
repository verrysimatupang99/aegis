"""Policy engine that enforces the Mythos constitution before any tool runs.

The engine is the single chokepoint between the agent's decision and the
filesystem/network. Every tool invocation goes through `check_action`. Hard-rule
violations raise `PolicyDenied`; soft-rule violations return warnings that the
caller surfaces to the user.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from .constitution import Constitution
from .journal import Journal


DESTRUCTIVE_ACTIONS = {
    "fs.delete",
    "fs.overwrite",
    "fs.chmod_open",
    "git.force_push",
    "git.reset_hard",
    "process.kill",
}

NETWORK_ACTIONS = {"net.http", "net.dns", "net.socket", "llm.call"}


class PolicyDenied(RuntimeError):
    def __init__(self, rule_id: str, message: str) -> None:
        super().__init__(f"[{rule_id}] {message}")
        self.rule_id = rule_id
        self.message = message


@dataclasses.dataclass
class Decision:
    allowed: bool
    warnings: tuple[str, ...] = ()
    rule_id: str | None = None
    reason: str = ""


@dataclasses.dataclass
class PolicyEngine:
    constitution: Constitution
    journal: Journal
    allow_exfil: tuple[str, ...] = ()
    i_mean_it: bool = False

    def check_action(self, action: str, ctx: dict[str, Any]) -> Decision:
        warnings: list[str] = []

        if action in DESTRUCTIVE_ACTIONS and not self.i_mean_it:
            self._journal_decision(action, ctx, "deny", "reversible_first")
            raise PolicyDenied(
                "reversible_first",
                f"action {action!r} is destructive; rerun with --i-mean-it",
            )

        if action in NETWORK_ACTIONS:
            host = str(ctx.get("host") or "")
            if not host:
                self._journal_decision(action, ctx, "deny", "no_silent_network")
                raise PolicyDenied(
                    "no_silent_network",
                    f"network action {action!r} missing host",
                )
            allowed = self.constitution.host_allowed(host) or host in self.allow_exfil
            if not allowed:
                self._journal_decision(action, ctx, "deny", "no_silent_network")
                raise PolicyDenied(
                    "no_silent_network",
                    f"host {host!r} not in network.allowlist",
                )
            if host in self.allow_exfil:
                warnings.append(
                    f"exfil-style call to {host!r} permitted by --allow-exfil"
                )

        if action == "fs.read":
            target = Path(str(ctx.get("path") or ""))
            sensitive = (".ssh", ".gnupg", "shadow", "authorized_keys")
            if any(part in str(target) for part in sensitive):
                warnings.append(
                    f"reading sensitive path {target}; values will not be echoed"
                )

        scope = ctx.get("scope")
        if scope == "/" and not ctx.get("scope_root_ack"):
            self._journal_decision(action, ctx, "deny", "small_blast_radius")
            raise PolicyDenied(
                "small_blast_radius",
                "whole-disk scope requires explicit acknowledgement",
            )

        self._journal_decision(action, ctx, "allow", None, warnings)
        return Decision(allowed=True, warnings=tuple(warnings))

    def _journal_decision(
        self,
        action: str,
        ctx: dict[str, Any],
        verdict: str,
        rule_id: str | None,
        warnings: list[str] | None = None,
    ) -> None:
        self.journal.write(
            "policy.decision",
            {
                "action": action,
                "verdict": verdict,
                "rule": rule_id,
                "warnings": warnings or [],
                "constitution_fp": self.constitution.fingerprint,
                "ctx": {k: v for k, v in ctx.items() if k != "secret"},
            },
        )
