"""Тонка обгортка над LLM API (Gemini через OpenAI-сумісний endpoint).

Обмеження (README):
  * модель викликаємо лише через офіційний `openai` SDK (без streaming);
  * модель — з LLM_MODEL, ключ — тільки з GEMINI_API_KEY.

Ретраї SDK вимкнені (max_retries=0): ретраями керує app.triage, щоб тримати загальний дедлайн.
"""
import os

from dotenv import load_dotenv
from openai import BadRequestError, OpenAI

load_dotenv()

MODEL = os.getenv("LLM_MODEL", "gemini-3.5-flash-lite")
BASE_URL = os.getenv("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")

_client = None
# Мінімальне «мислення» різко зменшує затримку. Якщо модель/endpoint його не приймає — вимикаємо.
_extra = {"reasoning_effort": "minimal"}


def get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(api_key=os.environ.get("GEMINI_API_KEY", ""), base_url=BASE_URL,
                         timeout=8.0, max_retries=0)
    return _client


def chat(messages, timeout: float = 8.0, **kwargs) -> str:
    """Надсилає повідомлення моделі й повертає текст відповіді ("" якщо порожньо)."""
    global _extra
    client = get_client().with_options(timeout=max(1.0, timeout), max_retries=0)
    params = {"temperature": 0, "max_tokens": 200, **_extra, **kwargs}
    try:
        resp = client.chat.completions.create(model=MODEL, messages=messages, **params)
    except BadRequestError:
        if "reasoning_effort" not in params:
            raise
        params = {k: v for k, v in params.items() if k != "reasoning_effort"}
        resp = client.chat.completions.create(model=MODEL, messages=messages, **params)
        _extra = {}  # вимикаємо лише якщо БЕЗ параметра запит пройшов — отже, 400 був через нього
    if not resp.choices:
        return ""
    return resp.choices[0].message.content or ""
