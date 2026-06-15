from __future__ import annotations

import json
import time
from typing import Any

import requests

from .common import compact
from .journal import RunJournal
from .settings import LlmSettings


class OptionalAdvisor:
    def __init__(self, settings: LlmSettings, policy: dict[str, Any], journal: RunJournal) -> None:
        self.settings = settings
        self.policy = policy
        self.journal = journal

    def explain(self, stage: str, error: str) -> str | None:
        if not self.settings.enabled or not self.settings.explain_errors:
            return None
        prompt = (
            "Ты консультант по локальной учебной Oracle CTF. "
            "Не создавай SQL и не предлагай обход прав. "
            "Кратко объясни ошибку и назови безопасную проверку.\n"
            f"Этап: {stage}\nОшибка: {compact(error, 1000)}\n"
            f"Правила: {json.dumps(self.policy.get('advisor_rules', []), ensure_ascii=False)}"
        )
        started = time.perf_counter()
        try:
            answer = self._request(prompt)
            self.journal.span(
                "llm.explain_error",
                "LLM",
                "OK",
                started,
                {"stage": stage, "error": error},
                {"answer": compact(answer, 1000)},
            )
            self.journal.event(
                "llm_advice",
                "success",
                {"stage": stage, "answer": compact(answer, 500)},
            )
            return answer
        except Exception as exc:
            self.journal.span(
                "llm.explain_error",
                "LLM",
                "ERROR",
                started,
                {"stage": stage},
                error=str(exc),
            )
            if self.settings.optional:
                self.journal.event(
                    "llm_advice",
                    "skipped",
                    {"reason": str(exc)},
                )
                return None
            raise

    def _request(self, prompt: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        if self.settings.api_type == "openai":
            response = requests.post(
                f"{self.settings.base_url}/chat/completions",
                headers=headers,
                json={
                    "model": self.settings.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "max_tokens": 180,
                },
                timeout=self.settings.timeout,
            )
            response.raise_for_status()
            choices = response.json().get("choices") or []
            return str(choices[0]["message"]["content"]) if choices else ""
        response = requests.post(
            f"{self.settings.base_url}/api/generate",
            json={
                "model": self.settings.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0, "num_predict": 180},
            },
            timeout=self.settings.timeout,
        )
        response.raise_for_status()
        return str(response.json().get("response", ""))
