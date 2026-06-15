from __future__ import annotations

import json
import logging
import time
from typing import Any

import requests
from pydantic import ValidationError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed

from .action_schema import OLLAMA_ACTION_SCHEMA, AgentAction


LOGGER = logging.getLogger(__name__)


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: int = 120,
        num_ctx: int = 4096,
        num_predict: int = 256,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.last_metrics: dict[str, Any] = {}

    def ensure_available(self) -> None:
        LOGGER.info("stage=ollama_check url=%s model=%s", self.base_url, self.model)
        started = time.perf_counter()
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
        LOGGER.info(
            "stage=ollama_ready model=%s duration_ms=%d",
            self.model,
            int((time.perf_counter() - started) * 1000),
        )

    @retry(
        retry=retry_if_exception_type(requests.ConnectionError),
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        reraise=True,
    )
    def _generate(self, prompt: str) -> dict[str, Any]:
        body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": OLLAMA_ACTION_SCHEMA,
            "options": {
                "temperature": 0,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
            },
            "keep_alive": "30m",
        }
        response = requests.post(
            f"{self.base_url}/api/generate",
            json=body,
            timeout=self.timeout,
        )
        if response.status_code == 400 and any(
            word in response.text.lower() for word in ("format", "schema")
        ):
            body["format"] = "json"
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=body,
                timeout=self.timeout,
            )
        response.raise_for_status()
        return response.json()

    def next_action(self, prompt: str) -> AgentAction:
        LOGGER.info(
            "stage=llm_request model=%s prompt_chars=%d num_ctx=%d num_predict=%d",
            self.model,
            len(prompt),
            self.num_ctx,
            self.num_predict,
        )
        started = time.perf_counter()
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
        self.last_metrics = {
            "total_ms": _ns_to_ms(payload.get("total_duration")),
            "load_ms": _ns_to_ms(payload.get("load_duration")),
            "prompt_tokens": payload.get("prompt_eval_count"),
            "prompt_ms": _ns_to_ms(payload.get("prompt_eval_duration")),
            "output_tokens": payload.get("eval_count"),
            "output_ms": _ns_to_ms(payload.get("eval_duration")),
            "wall_ms": int((time.perf_counter() - started) * 1000),
        }
        LOGGER.info(
            "stage=llm_response wall_ms=%s prompt_tokens=%s output_tokens=%s "
            "prompt_ms=%s output_ms=%s",
            self.last_metrics["wall_ms"],
            self.last_metrics["prompt_tokens"],
            self.last_metrics["output_tokens"],
            self.last_metrics["prompt_ms"],
            self.last_metrics["output_ms"],
        )
        try:
            return AgentAction.model_validate(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise OllamaError(f"Ollama returned invalid action JSON: {exc}") from exc
        except ValidationError as exc:
            details = exc.errors(include_url=False, include_input=False)
            raise OllamaError(
                f"Ollama action does not match schema: {json.dumps(details, ensure_ascii=False)}"
            ) from exc


def _ns_to_ms(value: Any) -> int | None:
    return int(value / 1_000_000) if isinstance(value, (int, float)) else None
