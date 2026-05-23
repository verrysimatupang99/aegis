"""Optional LLM bridge.

The LLM is treated as an *advisor*, not an executor. It receives redacted
context and returns suggestions; the policy engine still gates every action.
Network calls go through the policy engine's no_silent_network rule.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Any

from .policy import PolicyEngine


@dataclasses.dataclass
class LLMResponse:
    text: str
    model: str
    usage: dict[str, Any]


class LLMUnavailable(RuntimeError):
    pass


@dataclasses.dataclass
class LLM:
    policy: PolicyEngine
    model: str = "claude-3-5-sonnet-latest"

    def advise(self, system: str, user: str) -> LLMResponse:
        try:
            import anthropic  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dep
            raise LLMUnavailable(
                "anthropic SDK not installed. install extras with `pip install -e .[llm]`"
            ) from exc

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise LLMUnavailable("ANTHROPIC_API_KEY not set")

        self.policy.check_action(
            "llm.call",
            {"host": "api.anthropic.com", "model": self.model, "system_len": len(system)},
        )

        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(
            block.text for block in msg.content if getattr(block, "type", "") == "text"
        )
        return LLMResponse(
            text=text,
            model=self.model,
            usage={
                "input_tokens": msg.usage.input_tokens,
                "output_tokens": msg.usage.output_tokens,
            },
        )
