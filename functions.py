import os
import re
import shlex
import logging
import json
import ast
import time
import subprocess

from dotenv import load_dotenv
from groq import Groq

from config import *

load_dotenv()

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
DIRSEARCH_RESULT_RE = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]\s+(200|301|302|403)\s+-")

# =============================
# GROQ API KEY ROTATION
# =============================

_GROQ_API_KEYS = [
    os.getenv("GROQ_API_KEY1"),
    os.getenv("GROQ_API_KEY2"),
    os.getenv("GROQ_API_KEY3"),
    os.getenv("GROQ_API_KEY4"),

]

Prepare_api_key = os.getenv("API_KEY_pfe")

_CURRENT_KEY_INDEX = 0


def _get_groq_client():
    """Return Groq client with currently active API key."""
    global _CURRENT_KEY_INDEX
    active_key = _GROQ_API_KEYS[_CURRENT_KEY_INDEX]
    if not active_key:
        raise ValueError(f"No API key at index {_CURRENT_KEY_INDEX}")
    return Groq(api_key=active_key)


def _rotate_api_key():
    """Switch to next API key."""
    global _CURRENT_KEY_INDEX
    old_index = _CURRENT_KEY_INDEX
    _CURRENT_KEY_INDEX = (_CURRENT_KEY_INDEX + 1) % len(_GROQ_API_KEYS)
    logger.info(
        "Rotating API key from index %d to %d (rate limit detected)",
        old_index,
        _CURRENT_KEY_INDEX,
    )


client = _get_groq_client()

client_Prepare = Groq(api_key=Prepare_api_key)

OLLAMA_CLOUD_HOST = os.getenv("OLLAMA_CLOUD_HOST", "https://api.ollama.com")
OLLAMA_CLOUD_API_KEY = os.getenv("OLLAMA_CLOUD_API_KEY") or os.getenv("OLLAMA_API_KEY")

# =============================
# PLAIN-TEXT LLM (Groq)
# =============================


def _strip_thinking_tags(text: str) -> str:
    """Remove chain-of-thought <think>…</think> blocks."""
    return re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()


def call_llm_text(messages: list, model: str = None) -> str:
    """Call Groq for a free-form text response (no JSON schema).

    Mirrors call_llm's API-key rotation / retry behaviour but returns the raw
    assistant text with any <think> blocks stripped. Replaces the former
    Lightning AI client used by the conversation and news-curator agents.
    """
    use_model = model or MODEL
    max_retries = 3
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            active_client = _get_groq_client()
            response = active_client.chat.completions.create(
                model=use_model,
                messages=messages,
                temperature=0.3,
            )
            content = (response.choices[0].message.content or "").strip()
            if not content:
                raise ValueError("Empty response from LLM")
            return _strip_thinking_tags(content)

        except Exception as e:
            last_error = e
            error_str = str(e)
            if "429" in error_str or "Too Many Requests" in error_str:
                if attempt < max_retries:
                    logger.warning("HTTP 429 on attempt %d/%d — rotating API key", attempt, max_retries)
                    _rotate_api_key()
                    time.sleep(2 ** attempt)
                    continue
            if attempt < max_retries:
                logger.debug("call_llm_text error on attempt %d/%d: %s — retrying", attempt, max_retries, error_str)
                time.sleep(2 ** attempt)
                continue

    if last_error:
        raise last_error
    raise RuntimeError("call_llm_text failed: no error captured")


# =============================
# MCP EXECUTION
# =============================


# Per-tool execution timeouts (seconds). Slow recon tools get more room.
_TOOL_TIMEOUTS: dict = {
    "dirsearch":  90,
    "gobuster":   90,
    "amass":     180,
    "sublist3r":  60,
    "nmap":       60,
    "waybackurls": 30,
}
_DEFAULT_TIMEOUT = 40

# Lines to skip per tool (prefix tuples). Blank lines are always skipped globally.
_SKIP_PREFIXES: dict = {
    "whois": ("#", "%"),   # ARIN/RIPE registry comment blocks
}


def execute_command(cmd: str) -> str:
    parts = shlex.split(cmd)

    if not parts or parts[0] not in ALLOWED_COMMANDS:
        return "Command not allowed"

    tool = parts[0]
    timeout = _TOOL_TIMEOUTS.get(tool, _DEFAULT_TIMEOUT)

    try:
        process = subprocess.Popen(
            ["docker", "exec", "pentest-container", "bash", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            stdout_data, stderr_data = process.communicate(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            process.kill()
            stdout_data, stderr_data = process.communicate()
            timed_out = True

        skip_prefixes = _SKIP_PREFIXES.get(tool, ())

        results = []
        for line in stdout_data.splitlines():
            line = ANSI_ESCAPE_RE.sub("", line).strip()

            if not line:                                          # skip blank lines
                continue
            if skip_prefixes and line.startswith(skip_prefixes): # tool-specific noise
                continue
            if tool != "dirsearch" and line.startswith("["):     # nmap timestamp headers
                continue

            if tool == "dirsearch":
                if DIRSEARCH_RESULT_RE.search(line) and "/" in line:
                    results.append(line)
            else:
                results.append(line)

            if len(results) >= 50:
                break

        errors = [l.strip() for l in stderr_data.splitlines() if l.strip()]

        status = "TIMEOUT" if timed_out else ("SUCCESS" if process.returncode == 0 else "ERROR")
        prefix = f"(exceeded {timeout}s — partial output)\n" if timed_out else ""

        return (
            f"STATUS: {status}\n"
            f"FILTERED_OUTPUT:\n{prefix}{chr(10).join(results)}\n\n"
            f"ERRORS:\n{chr(10).join(errors)}\n"
        )

    except Exception as e:
        return f"ERROR: {str(e)}"


# =============================
# SCHEMA NORMALIZER
# =============================

def _groq_response_format(schema: dict) -> dict:
    inner = schema.get("input_schema") or schema.get("schema")
    if inner is None:
        raise ValueError(
            f"Schema dict for '{schema.get('name', '?')}' must contain either "
            "'input_schema' or 'schema'. Got keys: {list(schema.keys())}"
        )
    return {
        "type": "json_schema",
        "json_schema": {
            "name":   schema["name"],
            "strict": True,
            "schema": inner,
        },
    }


def _extract_object_text(raw: str) -> str:
    """Extract the most likely JSON object payload from a model response."""
    if not raw:
        return raw
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start >= 0 and end > start:
        return raw[start:end]
    return raw


def _parse_llm_json(content: str) -> dict:
    """Parse model output into a dict with tolerant fallbacks for near-JSON."""
    clean_json = _extract_object_text((content or "").strip())
    if not clean_json or clean_json == "{}":
        raise ValueError("Extracted JSON is empty")

    # Strict JSON path first.
    try:
        parsed = json.loads(clean_json)
        if not isinstance(parsed, dict) or not parsed:
            raise ValueError("Parsed JSON is empty")
        return parsed
    except Exception:
        pass

    # Common model mistakes: trailing commas and Python-style literals.
    repaired = re.sub(r",\s*([}\]])", r"\1", clean_json)
    repaired = re.sub(r"\bTrue\b", "true", repaired)
    repaired = re.sub(r"\bFalse\b", "false", repaired)
    repaired = re.sub(r"\bNone\b", "null", repaired)
    try:
        parsed = json.loads(repaired)
        if not isinstance(parsed, dict) or not parsed:
            raise ValueError("Parsed JSON is empty")
        return parsed
    except Exception:
        pass

    # Last resort: safely parse Python-literal dicts.
    try:
        parsed = ast.literal_eval(clean_json)
        if isinstance(parsed, dict) and parsed:
            return parsed
    except Exception:
        pass

    raise ValueError("Unable to parse LLM response into JSON object")


def _is_schema_validation_error(error_str: str) -> bool:
    s = (error_str or "").lower()
    return (
        "400" in s
        or "json_validate_failed" in s
        or "invalid_request_error" in s
    )


def _call_groq_json_fallback(
    *,
    client_obj,
    model: str,
    messages: list,
    schema: dict,
    max_tokens: int | None = None,
) -> dict:
    """
    Fallback path when provider-side JSON schema validation fails.
    Simplifies prompt to force valid JSON output.
    """
    schema_inner = schema.get("input_schema") or schema.get("schema") or schema

    # Extract property names for a concise schema reminder
    properties = schema_inner.get("properties", {})
    prop_names = list(properties.keys())

    fallback_messages = [
        {
            "role": "system",
            "content": f"Return ONLY valid JSON with these fields: {', '.join(prop_names)}. No markdown, no prose.",
        },
        *messages,
    ]

    kwargs = {
        "model": model,
        "messages": fallback_messages,
        "temperature": 0.05,  # Strict determinism for JSON
    }
    if max_tokens is not None:
        kwargs["max_tokens"] = max_tokens

    response = client_obj.chat.completions.create(**kwargs)
    content = (response.choices[0].message.content or "").strip()
    if not content:
        raise ValueError("Empty response from LLM fallback")
    return _parse_llm_json(content)


# =============================
# GENERIC LLM CALL (GROQ)
# =============================

def call_llm(messages: list, schema: dict) -> dict:

    # Build once — fail fast if the schema is malformed before hitting the network
    response_format = _groq_response_format(schema)

    max_retries = 3
    last_error  = None
    saw_schema_error = False
    _t0 = time.time()

    for attempt in range(1, max_retries + 1):
        try:
            active_client = _get_groq_client()
            response = active_client.chat.completions.create(
                model=MODEL,
                messages=messages,
                temperature=0.2,
                response_format=response_format,
            )

            content = (response.choices[0].message.content or "").strip()
            if not content:
                raise ValueError("Empty response from LLM")
            result = _parse_llm_json(content)
            return result

        except Exception as e:
            last_error = e
            error_str  = str(e)

            if "429" in error_str or "Too Many Requests" in error_str:
                if attempt < max_retries:
                    logger.warning(
                        "HTTP 429 on attempt %d/%d — rotating API key",
                        attempt, max_retries,
                    )
                    _rotate_api_key()
                    time.sleep(2 ** attempt)
                    continue

            if _is_schema_validation_error(error_str):
                saw_schema_error = True
                if attempt < max_retries:
                    logger.warning(
                        "HTTP 400 on attempt %d/%d — retrying: %s",
                        attempt, max_retries, error_str,
                    )
                    time.sleep(2 ** attempt)
                    continue

            if attempt < max_retries:
                logger.debug(
                    "LLM call error on attempt %d/%d: %s — retrying",
                    attempt, max_retries, error_str,
                )
                time.sleep(2 ** attempt)
                continue

    if saw_schema_error:
        try:
            logger.warning("Structured output failed after retries — trying non-strict JSON fallback")
            active_client = _get_groq_client()
            return _call_groq_json_fallback(
                client_obj=active_client,
                model=MODEL,
                messages=messages,
                schema=schema,
            )
        except Exception as fallback_error:
            logger.warning("Non-strict JSON fallback failed: %s", fallback_error)

    if last_error:
        raise last_error
    raise RuntimeError("call_llm failed: no error captured")


def call_llm_prep(messages: list, schema: dict, model: str = MODEL) -> dict:

    # Build once — fail fast if the schema is malformed before hitting the network
    response_format = _groq_response_format(schema)

    max_retries = 3
    last_error  = None
    saw_schema_error = False
    _t0 = time.time()

    for attempt in range(1, max_retries + 1):
        try:

            response = client_Prepare.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.2,
                response_format=response_format,
                max_tokens=65536,
            )

            content = (response.choices[0].message.content or "").strip()
            if not content:
                raise ValueError("Empty response from LLM")
            result = _parse_llm_json(content)
            return result

        except Exception as e:
            last_error = e
            error_str  = str(e)

            if "429" in error_str or "Too Many Requests" in error_str:
                if attempt < max_retries:
                    logger.warning(
                        "HTTP 429 on attempt %d/%d — rotating API key",
                        attempt, max_retries,
                    )
                    _rotate_api_key()
                    time.sleep(2 ** attempt)
                    continue

            if _is_schema_validation_error(error_str):
                saw_schema_error = True
                if attempt < max_retries:
                    logger.warning(
                        "HTTP 400 on attempt %d/%d — retrying: %s",
                        attempt, max_retries, error_str,
                    )
                    time.sleep(2 ** attempt)
                    continue

            if attempt < max_retries:
                logger.debug(
                    "LLM call error on attempt %d/%d: %s — retrying",
                    attempt, max_retries, error_str,
                )
                time.sleep(2 ** attempt)
                continue

    if saw_schema_error:
        try:
            logger.warning("Structured output failed after retries — trying non-strict JSON fallback")
            return _call_groq_json_fallback(
                client_obj=client_Prepare,
                model=model,
                messages=messages,
                schema=schema,
                max_tokens=65536,
            )
        except Exception as fallback_error:
            logger.warning("Non-strict JSON fallback failed: %s", fallback_error)

    if last_error:
        raise last_error
    raise RuntimeError("call_llm failed: no error captured")
