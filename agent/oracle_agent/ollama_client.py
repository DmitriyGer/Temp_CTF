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
        api_type: str = "auto",
        api_key: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.api_type = (
            "openai"
            if api_type == "auto" and self.base_url.endswith("/v1")
            else "ollama" if api_type == "auto" else api_type
        )
        self.api_key = api_key
        self.last_metrics: dict[str, Any] = {}

    def ensure_available(self) -> None:
        LOGGER.info(
            "stage=llm_check api=%s url=%s model=%s",
            self.api_type,
            self.base_url,
            self.model,
        )
        started = time.perf_counter()
        try:
            if self.api_type == "openai":
                response = self._get_openai_models()
            else:
                response = requests.get(
                    f"{self.base_url}/api/tags",
                    headers=self._headers(),
                    timeout=10,
                )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise OllamaError(
                f"LLM API ({self.api_type}) is unavailable at {self.base_url}: {exc}"
            ) from exc

        payload = response.json()
        if self.api_type == "openai":
            model_items = payload.get("data") or payload.get("models") or []
            models = {
                str(item.get("id") or item.get("name") or item.get("model") or "")
                for item in model_items
            }
        else:
            models = {
                item.get("name", "").split(":latest")[0]
                for item in payload.get("models", [])
            }
        if self.model not in models and not any(name.startswith(self.model) for name in models):
            hint = (
                f"Run: ollama pull {self.model}"
                if self.api_type == "ollama"
                else f"Available models: {', '.join(sorted(models)) or 'none'}"
            )
            raise OllamaError(f"Model {self.model!r} is unavailable. {hint}")
        LOGGER.info(
            "stage=llm_ready api=%s model=%s duration_ms=%d",
            self.api_type,
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
        if self.api_type == "openai":
            return self._generate_openai(prompt)
        return self._generate_ollama(prompt)

    def _generate_ollama(self, prompt: str) -> dict[str, Any]:
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

    def _generate_openai(self, prompt: str) -> dict[str, Any]:
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "max_tokens": self.num_predict,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "oracle_agent_action",
                    "strict": True,
                    "schema": OLLAMA_ACTION_SCHEMA,
                },
            },
        }
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers=self._headers(),
            json=body,
            timeout=self.timeout,
        )
        if response.status_code == 400:
            body["response_format"] = {"type": "json_object"}
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=body,
                timeout=self.timeout,
            )
        if response.status_code == 400:
            body.pop("response_format", None)
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
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

        if self.api_type == "openai":
            choices = payload.get("choices") or []
            raw = (
                choices[0].get("message", {}).get("content")
                if choices
                else None
            )
            usage = payload.get("usage") or {}
            self.last_metrics = {
                "total_ms": None,
                "load_ms": None,
                "prompt_tokens": usage.get("prompt_tokens"),
                "prompt_ms": None,
                "output_tokens": usage.get("completion_tokens"),
                "output_ms": None,
                "wall_ms": int((time.perf_counter() - started) * 1000),
            }
        else:
            raw = payload.get("response")
            self.last_metrics = {
                "total_ms": _ns_to_ms(payload.get("total_duration")),
                "load_ms": _ns_to_ms(payload.get("load_duration")),
                "prompt_tokens": payload.get("prompt_eval_count"),
                "prompt_ms": _ns_to_ms(payload.get("prompt_eval_duration")),
                "output_tokens": payload.get("eval_count"),
                "output_ms": _ns_to_ms(payload.get("eval_duration")),
                "wall_ms": int((time.perf_counter() - started) * 1000),
            }
        if not isinstance(raw, str) or not raw.strip():
            raise OllamaError("LLM API returned an empty response")
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

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _get_openai_models(self) -> requests.Response:
        response = requests.get(
            f"{self.base_url}/models",
            headers=self._headers(),
            timeout=10,
        )
        if response.status_code == 404:
            response = requests.get(
                f"{self.base_url}/mod",
                headers=self._headers(),
                timeout=10,
            )
        return response


def _ns_to_ms(value: Any) -> int | None:
    return int(value / 1_000_000) if isinstance(value, (int, float)) else None
