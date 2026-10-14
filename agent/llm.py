"""OpenAI-compatible LLM client (Person 3 owns).

Provider is chosen ONLY by .env, so you can switch any time without code changes:
    LLM_BASE_URL   e.g. https://api.xkiro.com/v1 (any OpenAI-compatible endpoint)
    LLM_API_KEY    your key (never commit, never send to the frontend)
    LLM_MODEL      model name for that provider
Starting point only: a connection test. The real intent parser is Person 3's task.
"""
import os
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def config_status() -> dict:
    """Which settings are present (values are never returned)."""
    return {
        "base_url": os.getenv("LLM_BASE_URL") or None,
        "model": os.getenv("LLM_MODEL") or None,
        "api_key_set": bool(os.getenv("LLM_API_KEY")),
    }


def get_client():
    from openai import OpenAI   # imported lazily so the rest of the app works without it

    base_url, key, model = os.getenv("LLM_BASE_URL"), os.getenv("LLM_API_KEY"), os.getenv("LLM_MODEL")
    missing = [n for n, v in (("LLM_BASE_URL", base_url), ("LLM_API_KEY", key), ("LLM_MODEL", model)) if not v]
    if missing:
        raise RuntimeError("Missing in .env: " + ", ".join(missing))
    return OpenAI(base_url=base_url, api_key=key, timeout=30), model


def test_connection() -> dict:
    """Send one tiny request. Returns ok / model / reply / latency, or ok=False with the error."""
    try:
        client, model = get_client()
        start = time.perf_counter()
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
            max_tokens=5,
            temperature=0,
        )
        return {
            "ok": True,
            "model": model,
            "reply": (resp.choices[0].message.content or "").strip(),
            "latency_ms": round((time.perf_counter() - start) * 1000),
        }
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
