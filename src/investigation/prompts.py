"""Prompt templates and versioned loader for FortiGate security investigations."""

from pathlib import Path
from typing import Tuple

_PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def load_prompt_with_version(filename: str) -> Tuple[str, str]:
    """Loads a prompt text file and extracts the version string from the header."""
    path = _PROMPTS_DIR / filename
    if not path.exists():
        return "1.0.0", ""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    version = "1.0.0"
    lines = content.splitlines()
    body_lines = []
    for line in lines:
        if line.startswith("# Version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("#"):
            continue
        else:
            body_lines.append(line)

    return version, "\n".join(body_lines).strip()


SYSTEM_PROMPT_VERSION, SYSTEM_PROMPT = load_prompt_with_version("system_v1.txt")
USER_PROMPT_VERSION, USER_PROMPT_TEMPLATE = load_prompt_with_version("user_v1.txt")


def build_user_prompt(packet_json: str, action_catalog_json: str, json_schema: str) -> str:
    """Renders the user prompt with untrusted data, schema, and eligible action catalog."""
    return USER_PROMPT_TEMPLATE.format(
        packet_json=packet_json,
        action_catalog_json=action_catalog_json,
        json_schema=json_schema,
    )
