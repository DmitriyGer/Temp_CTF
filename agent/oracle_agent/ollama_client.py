from __future__ import annotations

import json
from typing import Any

import requests
from pydantic import ValidationError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed

from .action_schema import AgentAction


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout: int = 120) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def ensure_available(self) -> None:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=10)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise OllamaError(f"Ollama is unavailable at {self.base_url}: {exc}") from exc

        models = {
            item.get("name", "").split(":latest")[0]
            for item in response.json().get("models", [])
        }
        if self.model not in models and not any(name.startswith(self.model) for name in models):
            raise OllamaError(
                f"Model {self.model!r} is not installed. Run: ollama pull {self.model}"
            )

    @retry(
        retry=retry_if_exception_type(requests.RequestException),
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        reraise=True,
    )
    def _generate(self, prompt: str) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def next_action(self, prompt: str) -> AgentAction:
        try:
            payload = self._generate(prompt)
        except requests.Timeout as exc:
            raise OllamaError(f"Ollama request timed out after {self.timeout}s") from exc
        except requests.RequestException as exc:
            message = str(exc)
            if "404" in message:
                message += f". Run: ollama pull {self.model}"
            raise OllamaError(f"Ollama request failed: {message}") from exc

        raw = payload.get("response")
        if not isinstance(raw, str) or not raw.strip():
            raise OllamaError("Ollama returned an empty response")
        try:
            return AgentAction.model_validate(json.loads(raw))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise OllamaError(f"Ollama returned invalid action JSON: {exc}") from exc
