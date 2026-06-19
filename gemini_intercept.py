"""
gemini_intercept.py — mitmproxy addon
Intercepts Gemini streaming responses via the batchexecute endpoint,
prints to terminal, and saves each chat to its own file.

Usage:
    mitmdump -s gemini_intercept.py

Set chat name:
    GEMINI_CHAT_NAME="my_chat" mitmdump -s gemini_intercept.py
"""

import json
import os
import re
from datetime import datetime

from mitmproxy import http

# ── Config ────────────────────────────────────────────────────────────────────

SAVE_DIR = "gemini_chats"
DEFAULT_CHAT_NAME = "my_chat"

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_chat_name() -> str:
    return os.environ.get("GEMINI_CHAT_NAME", DEFAULT_CHAT_NAME)


def get_chat_file() -> str:
    os.makedirs(SAVE_DIR, exist_ok=True)
    safe = re.sub(r"[^\w\-]", "_", get_chat_name())
    return os.path.join(SAVE_DIR, f"{safe}.txt")


def walk_for_text(node, depth=0) -> str:
    """Recursively walk a parsed JSON structure, return longest text found."""
    if depth > 10:
        return ""
    if isinstance(node, str):
        return node if is_likely_response(node) else ""
    if isinstance(node, list):
        best = ""
        for item in node:
            t = walk_for_text(item, depth + 1)
            if len(t) > len(best):
                best = t
        return best
    if isinstance(node, dict):
        best = ""
        for v in node.values():
            t = walk_for_text(v, depth + 1)
            if len(t) > len(best):
                best = t
        return best
    return ""


def is_likely_response(text: str) -> bool:
    """Heuristic: model responses are multi-word, not URLs or base64 blobs."""
    if len(text) < 20:
        return False
    if text.startswith("http"):
        return False
    if re.match(r'^[A-Za-z0-9+/=]+$', text):  # base64
        return False
    if text.startswith("function") or text.startswith("var "):
        return False
    return text.count(" ") > 3


def extract_text_from_batchexecute(raw: str) -> str:
    """
    Gemini uses Google's batchexecute wire format:
        )]}'\n\n[[[\"wrb.fr\",\"...\",\"[JSON string]\",...]]]

    The inner payload is a double-encoded JSON string. We extract all
    candidate strings, try to parse them, and walk for the longest
    human-readable text (the model's response).
    """
    candidates = re.findall(r'\"((?:[^"\\]|\\.){100,})\"', raw)

    best = ""
    for c in candidates:
        try:
            unescaped = c.encode().decode("unicode_escape")
        except Exception:
            unescaped = c

        try:
            data = json.loads(unescaped)
            text = walk_for_text(data)
            if text and len(text) > len(best):
                best = text
        except Exception:
            stripped = c.strip()
            if len(stripped) > len(best) and is_likely_response(stripped):
                best = stripped

    return best.strip()


def extract_prompt(flow: http.HTTPFlow) -> str:
    """Pull user prompt from the batchexecute POST body (f.req field)."""
    try:
        body = flow.request.content.decode("utf-8", errors="ignore")
        match = re.search(r'f\.req=([^&]+)', body)
        if match:
            from urllib.parse import unquote
            freq = unquote(match.group(1))
            data = json.loads(freq)
            text = walk_for_text(data)
            if text and len(text) < 2000:
                return text.strip()
    except Exception:
        pass
    return ""


def print_response(prompt: str, full_text: str) -> None:
    width = 72
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    chat_name = get_chat_name()

    print(f"\n┌{'─'*width}┐")
    print(f"│ 💬 Chat : {chat_name:<{width-10}}│")
    print(f"│ 🕐 Time : {ts:<{width-10}}│")
    print(f"├{'─'*width}┤")
    if prompt:
        print(f"│ YOU:{'':<{width-4}}│")
        for line in prompt.splitlines():
            for chunk in [line[i:i+width-2] for i in range(0, max(len(line), 1), width-2)]:
                print(f"│  {chunk:<{width-2}}│")
        print(f"├{'─'*width}┤")
    print(f"│ GEMINI:{'':<{width-7}}│")
    for line in full_text.splitlines():
        for chunk in [line[i:i+width-2] for i in range(0, max(len(line), 1), width-2)]:
            print(f"│  {chunk:<{width-2}}│")
    print(f"└{'─'*width}┘\n")


def save_to_file(prompt: str, full_text: str) -> None:
    path = get_chat_file()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*72}\n")
        f.write(f"[{ts}]\n")
        if prompt:
            f.write(f"\nYOU:\n{prompt}\n")
        f.write(f"\nGEMINI:\n{full_text}\n")
    print(f"  ✅ Saved → {path}")


# ── mitmproxy hooks ───────────────────────────────────────────────────────────

_prompts: dict[str, str] = {}


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    path = flow.request.path
    if "gemini.google.com" not in host:
        return
    if "batchexecute" not in path and "BardChatUi" not in path:
        return
    _prompts[flow.id] = extract_prompt(flow)


def response(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    path = flow.request.path
    if "gemini.google.com" not in host:
        return
    if "batchexecute" not in path and "BardChatUi" not in path:
        return
    if len(flow.response.content) < 200:
        return

    raw = flow.response.content.decode("utf-8", errors="ignore")
    full_text = extract_text_from_batchexecute(raw)

    if not full_text:
        return

    prompt = _prompts.pop(flow.id, "")
    print_response(prompt, full_text)
    save_to_file(prompt, full_text)