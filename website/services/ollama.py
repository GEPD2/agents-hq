import json
import os
import re
import urllib.request

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "localhost")
OLLAMA_PORT = int(os.environ.get("OLLAMA_PORT", "11434"))
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:14b")

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def chat(messages: list[dict], model: str | None = None, timeout: int = 240) -> str:
    """Non-streaming chat call to Ollama. Returns assistant text, <think> stripped."""
    payload = json.dumps({
        "model": model or OLLAMA_MODEL,
        "messages": messages,
        "stream": True,
    }).encode()
    req = urllib.request.Request(
        f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/chat",
        data=payload, headers={"Content-Type": "application/json"}, method="POST",
    )
    full = ""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw in resp:
                line = raw.decode().strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    full += obj.get("message", {}).get("content", "")
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        return f"[OLLAMA] Error: {e}"
    return _THINK_RE.sub("", full).strip()


def is_available() -> bool:
    try:
        url = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/tags"
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status == 200
    except Exception:
        return False
