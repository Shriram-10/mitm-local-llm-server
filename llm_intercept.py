"""
llm_intercept.py — mitmproxy addon
Intercepts responses from Gemini, Claude, ChatGPT, Grok, and Copilot.
Prints to terminal and saves per chat to files.

Usage:
    mitmdump -s llm_intercept.py

Set chat name:
    CHAT_NAME="my_research" mitmdump -s llm_intercept.py

Debug mode:
    LLM_DEBUG=1 mitmdump -s llm_intercept.py
"""

import json
import os
import re
from datetime import datetime
from mitmproxy import http

# ── Config ────────────────────────────────────────────────────────────────────

SAVE_DIR = "llm_chats"
DEFAULT_CHAT_NAME = "my_chat"
DEBUG = os.environ.get("LLM_DEBUG", "0") == "1"

# ── Platform definitions ──────────────────────────────────────────────────────

PLATFORMS = {
    "gemini": {
        "hosts":   ["gemini.google.com"],
        "paths":   ["BardChatUi", "batchexecute"],
        "exclude": [],
        "format":  "batchexecute",
        "label":   "GEMINI",
        "icon":    "🟦",
    },
    "claude": {
        "hosts":   ["claude.ai"],
        "paths":   ["/api/organizations"],
        "exclude": [],
        "format":  "sse",
        "sse_key": ["delta", "text"],
        "label":   "CLAUDE",
        "icon":    "🟠",
    },
    "chatgpt": {
        "hosts":   ["chatgpt.com", "api.openai.com"],
        "paths":   ["backend-api/f/conversation"],
        "exclude": ["prepare", "feedback", "rating"],
        "format":  "chatgpt_delta",
        "label":   "CHATGPT",
        "icon":    "🟢",
    },
    "grok": {
        # grok.com/rest/app-chat/conversations/<id>/responses
        "hosts":   ["grok.com", "x.ai"],
        "paths":   ["/rest/app-chat/conversations/"],
        "path_suffix": ["responses"],        # must also appear in path
        "exclude": [],
        "format":  "grok_json",
        "label":   "GROK",
        "icon":    "⚡",
    },
    "deepseek": {
        "hosts":   ["chat.deepseek.com", "deepseek.com"],
        "paths":   ["/api/v0/chat/completion"],
        "exclude": [],
        "format":  "deepseek_delta",
        "label":   "DEEPSEEK",
        "icon":    "🐋",
    },
    "copilot": {
        "hosts":   ["copilot.microsoft.com", "sydney.bing.com"],
        "paths":   ["c/api/chat", "edgesvc/chat"],
        "exclude": [],
        "format":  "copilot_ws",          # WebSocket — handled in websocket_message hook
        "label":   "COPILOT",
        "icon":    "🔵",
    },
}

# ── State ─────────────────────────────────────────────────────────────────────

_prompts: dict[str, str] = {}

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_chat_name() -> str:
    return os.environ.get("CHAT_NAME", DEFAULT_CHAT_NAME)


def get_chat_file(platform: str) -> str:
    os.makedirs(SAVE_DIR, exist_ok=True)
    safe_chat = re.sub(r"[^\w\-]", "_", get_chat_name())
    return os.path.join(SAVE_DIR, f"{safe_chat}__{platform}.txt")


def detect_platform(flow: http.HTTPFlow) -> dict | None:
    host = flow.request.pretty_host
    path = flow.request.path
    for name, p in PLATFORMS.items():
        if any(h in host for h in p["hosts"]):
            if any(seg in path for seg in p["paths"]):
                # optional: all path_suffix entries must also be in path
                if any(ex in path for ex in p.get("exclude", [])):
                    return None
                suffixes = p.get("path_suffix", [])
                if suffixes and not all(s in path for s in suffixes):
                    continue
                return {"name": name, **p}
    return None


# ── Format parsers ────────────────────────────────────────────────────────────

def deep_get(data, keys: list):
    node = data
    for k in keys:
        try:
            node = node[k]
        except (KeyError, IndexError, TypeError):
            return None
    return node


def parse_sse(raw: str, sse_key: list) -> str:
    """Standard SSE: each data line is JSON, walk sse_key to get text."""
    chunks = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload in ("[DONE]", ""):
            continue
        try:
            data = json.loads(payload)
            text = deep_get(data, sse_key)
            if isinstance(text, str) and text:
                chunks.append(text)
        except json.JSONDecodeError:
            pass
    return "".join(chunks).strip()


def parse_chatgpt_delta(raw: str) -> str:
    """
    ChatGPT delta_encoding v1 format:
      First chunk: {"p": "/message/content/parts/0", "o": "append", "v": "Oh, it"}
      All others:  {"v": " can get spectacularly bad."}
    Every text delta has a "v" string — collect and concatenate in order.
    Ignore chunks where "v" is a dict/list (those are metadata, not text).
    """
    chunks = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload.startswith('"'):
            continue
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            v = data.get("v")
            if isinstance(v, str) and v:
                chunks.append(v)
    return "".join(chunks).strip()


def parse_grok_json(raw: str) -> tuple[str, str]:
    """
    Grok returns a single JSON object (not SSE):
    {
      "result": {
        "userResponse": { "message": "<user prompt>", ... },
        "modelResponse": { "message": "<grok reply>", ... }
      }
    }
    Returns (prompt, response) tuple.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Sometimes the body is newline-delimited JSON objects (streaming variant)
        # Try parsing each line and return the richest one
        best_prompt = ""
        best_response = ""
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                result = obj.get("result", {})
                user_msg = deep_get(result, ["userResponse", "message"]) or ""
                model_msg = deep_get(result, ["modelResponse", "message"]) or ""
                if len(model_msg) > len(best_response):
                    best_prompt = user_msg
                    best_response = model_msg
            except json.JSONDecodeError:
                continue
        return best_prompt.strip(), best_response.strip()

    result = data.get("result", {})

    prompt   = deep_get(result, ["userResponse",  "message"]) or ""
    response = deep_get(result, ["modelResponse", "message"]) or ""

    # Fallback: sometimes it's nested under "responses" list
    if not response:
        responses = result.get("responses", [])
        for r in responses:
            msg = r.get("message", "")
            if msg and len(msg) > len(response):
                response = msg

    return prompt.strip(), response.strip()


def is_likely_response(text: str) -> bool:
    if len(text) < 20:
        return False
    if text.startswith("http"):
        return False
    if re.match(r'^[A-Za-z0-9+/=]+$', text):
        return False
    if text.startswith(("function", "var ", "const ", "let ")):
        return False
    return text.count(" ") > 3


def walk_for_text(node, depth=0) -> str:
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


def parse_batchexecute(raw: str) -> str:
    """Gemini's double-encoded batchexecute wire format."""
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



def parse_copilot_ws(chunks: list[str]) -> str:
    """
    Copilot WS event protocol:
      {"event":"connected"}            — handshake, ignore
      {"event":"received"}             — user message ack, ignore
      {"event":"startMessage","messageId":"..."} — start of AI response
      {"event":"appendText","messageId":"...","text":"..."} — stream chunk
      {"event":"endMessage","messageId":"..."}  — response complete
    We accumulate appendText chunks and return on endMessage.
    chunks is the list of raw JSON strings for one messageId.
    """
    parts = []
    for raw in chunks:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if data.get("event") == "appendText":
            text = data.get("text", "")
            if isinstance(text, str) and text:
                parts.append(text)
    return "".join(parts).strip()


def parse_deepseek_delta(raw: str) -> str:
    """
    DeepSeek SSE delta format:
      - First substantive chunk: {"v": {"response": {"fragments": [{"content": "Hey", ...}], ...}}}
        → grab fragments[0].content (and any subsequent fragments)
      - APPEND deltas: {"p": "response/fragments/-1/content", "o": "APPEND", "v": " there"}
        → v is a string, append it
      - Simple deltas: {"v": "!"}  {"v": " 👋"}
        → v is a string, append it
      Ignore: event:ready, event:update_session, and any {"v": {}} where v is a non-response dict.
    """
    chunks = []
    seen_initial = False
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload:
            continue
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        v = data.get("v")
        # String delta — most common after the first chunk
        # Filter out known non-content status tokens
        if isinstance(v, str) and v and v not in ("FINISHED", "DONE", "END", "[DONE]"):
            chunks.append(v)
        # Object delta — first real content chunk
        elif isinstance(v, dict) and not seen_initial:
            fragments = deep_get(v, ["response", "fragments"]) or []
            for frag in fragments:
                text = frag.get("content", "")
                if isinstance(text, str) and text:
                    chunks.append(text)
            seen_initial = True
    return "".join(chunks).strip()


def extract_response(raw: str, platform: dict) -> tuple[str, str]:
    """
    Returns (prompt_override, response_text).
    prompt_override is non-empty only when the format embeds the prompt
    (currently only grok_json). Callers should prefer it over _prompts cache
    when non-empty.
    """
    fmt = platform["format"]
    if fmt == "batchexecute":
        return "", parse_batchexecute(raw)
    if fmt == "sse":
        return "", parse_sse(raw, platform.get("sse_key", ["text"]))
    if fmt == "chatgpt_delta":
        return "", parse_chatgpt_delta(raw)
    if fmt == "grok_json":
        prompt, response = parse_grok_json(raw)
        return prompt, response
    if fmt == "deepseek_delta":
        return "", parse_deepseek_delta(raw)
    if fmt == "copilot_ws":
        return "", parse_copilot_ws(raw)
    return "", ""


# ── Prompt extraction ─────────────────────────────────────────────────────────

def extract_prompt(flow: http.HTTPFlow, platform: dict) -> str:
    try:
        body = flow.request.content.decode("utf-8", errors="ignore")
        if platform["format"] == "batchexecute":
            match = re.search(r'f\.req=([^&]+)', body)
            if match:
                from urllib.parse import unquote
                data = json.loads(unquote(match.group(1)))
                text = walk_for_text(data)
                if text and len(text) < 2000:
                    return text.strip()
        elif platform["format"] == "grok_json":
            # Grok request body: {"message": "...", "modelName": "...", ...}
            data = json.loads(body)
            for key in ["message", "query", "prompt", "text"]:
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        elif platform["format"] == "deepseek_delta":
            data = json.loads(body)
            # DeepSeek request: {"message": "...", "chat_session_id": "...", ...}
            for key in ["message", "prompt", "query", "text"]:
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        else:
            data = json.loads(body)
            for path in [
                ["prompt"],
                ["messages", -1, "content"],
                ["query"],
                ["text"],
            ]:
                text = deep_get(data, path)
                if isinstance(text, str) and text.strip():
                    return text.strip()
    except Exception:
        pass
    return ""


def extract_chatgpt_prompt(raw: str) -> str:
    """
    ChatGPT includes the user message in the stream itself as an input_message event.
    Pull it from there since the request body doesn't contain plaintext.
    """
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        try:
            data = json.loads(payload)
            if data.get("type") == "input_message":
                parts = deep_get(data, ["input_message", "content", "parts"])
                if isinstance(parts, list) and parts:
                    return str(parts[0]).strip()
        except Exception:
            pass
    return ""


# ── Output ────────────────────────────────────────────────────────────────────

def print_response(prompt: str, full_text: str, platform: dict) -> None:
    width = 72
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    icon = platform["icon"]
    label = platform["label"]
    chat_name = get_chat_name()

    print(f"\n┌{'─'*width}┐")
    print(f"│ {icon} {label:<10} chat: {chat_name:<{width-20}}│")
    print(f"│ 🕐 {ts:<{width-4}}│")
    print(f"├{'─'*width}┤")
    if prompt:
        print(f"│ YOU:{'':<{width-4}}│")
        for line in prompt.splitlines():
            for chunk in [line[i:i+width-2] for i in range(0, max(len(line), 1), width-2)]:
                print(f"│  {chunk:<{width-2}}│")
        print(f"├{'─'*width}┤")
    print(f"│ {label}:{'':<{width-len(label)-1}}│")
    for line in full_text.splitlines():
        for chunk in [line[i:i+width-2] for i in range(0, max(len(line), 1), width-2)]:
            print(f"│  {chunk:<{width-2}}│")
    print(f"└{'─'*width}┘\n")


def save_to_file(prompt: str, full_text: str, platform: dict) -> None:
    path = get_chat_file(platform["name"])
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*72}\n")
        f.write(f"[{ts}] [{platform['label']}]\n")
        if prompt:
            f.write(f"\nYOU:\n{prompt}\n")
        f.write(f"\n{platform['label']}:\n{full_text}\n")
    print(f"  ✅ Saved → {path}")


def debug_flow(flow: http.HTTPFlow, platform: dict) -> None:
    print(f"\n[DEBUG] {platform['label']} | {flow.request.method} {flow.request.path}")
    print(f"[DEBUG] response size: {len(flow.response.content)}b")
    print(f"[DEBUG] raw preview:\n{flow.response.content[:600]}\n")


# Per-WebSocket accumulated message buffer (keyed by flow.id)
_ws_buffers: dict[str, list[str]] = {}


# ── mitmproxy hooks ───────────────────────────────────────────────────────────

def websocket_message(flow: http.HTTPFlow) -> None:
    """Handle WebSocket messages — used for Copilot."""
    platform = detect_platform(flow)
    if not platform or platform["format"] != "copilot_ws":
        return

    msg = flow.websocket.messages[-1]
    raw = msg.content if isinstance(msg.content, str) else msg.content.decode("utf-8", errors="ignore")

    try:
        data = json.loads(raw)
    except Exception:
        return

    event = data.get("event", "")

    # Outbound: user sends their prompt
    if msg.from_client:
        # Copilot send event: {"event":"send","content":[{"type":"text","text":"..."}],...}
        if event == "send":
            parts = data.get("content", [])
            if isinstance(parts, list):
                texts = [p.get("text", "") for p in parts if p.get("type") == "text"]
                prompt_text = " ".join(t for t in texts if t).strip()
                if prompt_text:
                    _prompts[flow.id] = prompt_text
        return

    # startMessage — pre-initialize buffer for this messageId
    if event == "startMessage":
        msg_id = data.get("messageId", flow.id)
        _ws_buffers[msg_id] = []
        return

    # appendText — lazy-init buffer if startMessage was missed, then accumulate
    if event == "appendText":
        msg_id = data.get("messageId", flow.id)
        if msg_id not in _ws_buffers:
            _ws_buffers[msg_id] = []
        _ws_buffers[msg_id].append(raw)
        return

    # Terminal events — flush whichever buffer has data
    if event in ("endMessage", "done", "complete", "finishedMessage", "end"):
        msg_id = data.get("messageId", "")
        # Try by messageId first, then fall back to any non-empty buffer
        chunks = _ws_buffers.pop(msg_id, None)
        if chunks is None:
            # Pick the largest non-empty buffer (handles missed startMessage)
            if _ws_buffers:
                msg_id = max(_ws_buffers, key=lambda k: len(_ws_buffers[k]))
                chunks = _ws_buffers.pop(msg_id, [])
            else:
                chunks = []
        if not chunks:
            return
        full_text = parse_copilot_ws(chunks)
        if not full_text:
            return
        prompt = _prompts.pop(flow.id, "")
        print_response(prompt, full_text, platform)
        save_to_file(prompt, full_text, platform)


def request(flow: http.HTTPFlow) -> None:
    platform = detect_platform(flow)
    if not platform:
        return
    _prompts[flow.id] = extract_prompt(flow, platform)


def response(flow: http.HTTPFlow) -> None:
    platform = detect_platform(flow)
    if not platform:
        return

    # (debug dumps removed)

    if DEBUG:
        debug_flow(flow, platform)

    if len(flow.response.content) < 200:
        return

    raw = flow.response.content.decode("utf-8", errors="ignore")
    prompt_override, full_text = extract_response(raw, platform)

    if not full_text:
        return

    if platform["name"] == "chatgpt":
        prompt = extract_chatgpt_prompt(raw)
    elif prompt_override:
        # grok_json already extracted the prompt from the response body
        prompt = prompt_override
        _prompts.pop(flow.id, None)
    else:
        prompt = _prompts.pop(flow.id, "")

    print_response(prompt, full_text, platform)
    save_to_file(prompt, full_text, platform)