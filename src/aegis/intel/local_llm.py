"""Local LLM adapter (Ollama-compatible).

Runs entirely against http://localhost (or AEGIS_OLLAMA_HOST). It still goes
through the policy gate, but the constitution treats `localhost` as allowed by
default for local-LLM calls. Useful when the user wants advisory output
without any data leaving the machine.
"""

from __future__ import annotations

import dataclasses
import json
import os
import urllib.error
import urllib.request

from ..core.policy import PolicyEngine


@dataclasses.dataclass
class LocalLLMResponse:
    text: str
    model: str
    host: str


class LocalLLMUnavailable(RuntimeError):
    pass


@dataclasses.dataclass
class LocalLLM:
    policy: PolicyEngine
    model: str = "llama3.1"
    host: str = dataclasses.field(
        default_factory=lambda: os.environ.get("AEGIS_OLLAMA_HOST", "http://127.0.0.1:11434")
    )
    timeout: float = 60.0

    def advise(self, system: str, user: str) -> LocalLLMResponse:
        host_only = self.host.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        self.policy.check_action(
            "llm.call",
            {"host": host_only, "model": self.model, "system_len": len(system), "local": True},
        )
        body = json.dumps(
            {
                "model": self.model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host.rstrip('/')}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError) as exc:
            raise LocalLLMUnavailable(
                f"could not reach Ollama at {self.host}: {exc}"
            ) from exc
        text = (payload.get("message") or {}).get("content") or payload.get("response") or ""
        return LocalLLMResponse(text=text, model=self.model, host=self.host)
