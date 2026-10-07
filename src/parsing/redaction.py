"""Security redaction, URL parameter stripping, and untrusted evidence delimiting."""

import re
import hashlib
import urllib.parse
from typing import Dict, Any, Optional

# Remove ANSI control sequences and non-printable control characters
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def redact_url(url: Optional[str]) -> Optional[str]:
    """Reduces a URL to scheme, host, and path, preserving query parameter names while stripping values."""
    if not url:
        return None
    try:
        parsed = urllib.parse.urlsplit(url.strip())
        if not parsed.scheme and not parsed.netloc:
            # Relative path or fragment
            path = parsed.path
            if parsed.query:
                # Retain query keys without values
                q_keys = [k for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
                path = f"{path}?{'&'.join(f'{k}=<redacted>' for k in q_keys)}"
            return path

        new_query = ""
        if parsed.query:
            q_keys = [k for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
            new_query = "&".join(f"{k}=<redacted>" for k in q_keys)

        return urllib.parse.urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            new_query,
            "",  # Strip fragment
        ))
    except Exception:
        return "[INVALID_URL]"


def clean_and_truncate_text(text: Optional[str], max_len: int = 160) -> Optional[str]:
    """Strips control characters, normalizes whitespace, and truncates to max_len."""
    if not text:
        return None
    cleaned = CONTROL_CHARS_PATTERN.sub("", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return cleaned


def sanitize_username(username: Optional[str], include_usernames: bool = False) -> Optional[str]:
    """Hashes usernames unless explicitly permitted by configuration."""
    if not username:
        return None
    if include_usernames:
        return username
    h = hashlib.sha256(username.strip().encode("utf-8")).hexdigest()[:8]
    return f"user_{h}"


def wrap_untrusted_evidence(evidence_id: str, content: str) -> str:
    """Delimits evidence item in prompt with strict <<UNTRUSTED>> delimiters."""
    clean_content = content.replace("<<UNTRUSTED", "[ESCAPED_UNTRUSTED").replace("<</UNTRUSTED>>", "[ESCAPED_UNTRUSTED_END]")
    return f"<<UNTRUSTED id={evidence_id}>>\n{clean_content}\n<</UNTRUSTED>>"


def redact_evidence_record(record: Dict[str, Any], include_usernames: bool = False) -> Dict[str, Any]:
    """Produces a sanitized, model-safe view of an evidence event."""
    redacted = dict(record)

    # Sanitize URL
    if "url" in redacted and redacted["url"]:
        redacted["url"] = redact_url(redacted["url"])

    # Sanitize msg
    if "msg" in redacted and redacted["msg"]:
        redacted["msg"] = clean_and_truncate_text(redacted["msg"], max_len=160)

    # Sanitize user agent if present
    if "user_agent" in redacted and redacted["user_agent"]:
        redacted["user_agent"] = clean_and_truncate_text(redacted["user_agent"], max_len=80)

    # Sanitize username if present
    if "user" in redacted and redacted["user"]:
        redacted["user"] = sanitize_username(redacted["user"], include_usernames=include_usernames)

    # Never expose raw_message to model
    redacted.pop("raw_message", None)

    return redacted
