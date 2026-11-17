import json
import logging
import pathlib
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_REGISTRY_DIR = pathlib.Path(__file__).resolve().parent.parent / "prompts"
_MANIFEST_PATH = pathlib.Path(__file__).resolve().parent.parent / "prompts" / "prompt_registry.json"

_TEMPLATE_VAR_RE = re.compile(r"{{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*}}")


def render_template(template: str, values: Dict[str, Any]) -> str:
    """Fill a prompt template's ``{{var}}`` placeholders from ``values``.

    Replaces the MLflow PromptVersion.format() behaviour: snapshot templates use
    ``{{name}}`` placeholders, which Python's str.format() would mishandle.
    Unknown placeholders are left verbatim.
    """
    if not template:
        return ""

    def _replace(match: "re.Match") -> str:
        key = match.group(1)
        return str(values.get(key, match.group(0)))

    return _TEMPLATE_VAR_RE.sub(_replace, template)


def _resolve_latest_version(prompt_name: str) -> str:
    """Return the highest integer version available on disk for a prompt name."""
    prompt_dir = _REGISTRY_DIR / prompt_name
    if not prompt_dir.is_dir():
        raise FileNotFoundError(f"No prompt directory for '{prompt_name}' in {_REGISTRY_DIR}")
    versions = []
    for f in prompt_dir.glob("*.json"):
        try:
            versions.append(int(f.stem))
        except ValueError:
            continue
    if not versions:
        raise FileNotFoundError(f"No versioned prompt snapshots in {prompt_dir}")
    return str(max(versions))


def load_prompt_from_registry(prompt_name: str, prompt_version: str) -> Dict[str, Any]:
    """Load a prompt snapshot from the local file registry (prompts/<name>/<version>.json).

    Pass prompt_version="latest" to load the highest version available on disk.
    """
    if str(prompt_version) == "latest":
        prompt_version = _resolve_latest_version(prompt_name)

    target_path = _REGISTRY_DIR / prompt_name / f"{prompt_version}.json"
    if not target_path.exists():
        raise FileNotFoundError(f"Prompt snapshot not found: {target_path}")

    payload = json.loads(target_path.read_text(encoding="utf-8"))
    logger.info("Prompt loaded from registry: %s v%s", prompt_name, prompt_version)
    return payload


def require_prompt_tag(payload: Dict[str, Any], tag_key: str) -> str:
    tags = payload.get("tags") or {}
    value = tags.get(tag_key)
    if value is None or str(value).strip() == "":
        raise ValueError(f"Prompt {payload.get('uri')} missing required tag: {tag_key}")
    return str(value)


def load_registry_manifest(manifest_path: pathlib.Path | None = None) -> List[Dict[str, str]]:
    path = manifest_path or _MANIFEST_PATH
    if not path.exists():
        raise FileNotFoundError(f"Prompt registry manifest not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    prompts = payload.get("prompts") if isinstance(payload, dict) else []
    if not isinstance(prompts, list):
        raise ValueError(f"Invalid prompt registry manifest format: {path}")
    normalized: List[Dict[str, str]] = []
    for item in prompts:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        if name and version:
            normalized.append({"name": name, "version": version})
    return normalized


def sync_required_prompts(manifest_path: pathlib.Path | None = None) -> List[Dict[str, Any]]:
    synced: List[Dict[str, Any]] = []
    for prompt in load_registry_manifest(manifest_path):
        synced.append(load_prompt_from_registry(prompt["name"], prompt["version"]))
    return synced
