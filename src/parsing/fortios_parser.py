"""High-performance FortiOS key-value log lexer and parser.

Handles syslog headers, quoted strings with spaces/escaped quotes,
unquoted tokens, IPv6, and malformed fragments.
"""

import re
from typing import Dict, Any, Optional

# Regex to strip common syslog header prefixes if present
# e.g., "<189>date=2026-10-06..." or "Oct  6 12:00:00 fortigate date=..."
SYSLOG_PREFIX_PATTERN = re.compile(r"^<\d+>|^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+[\w\.-]+(?:\s+[\w\.-]+)?:\s*")


def parse_fortios_line(raw_line: str) -> Dict[str, str]:
    """Parse a single FortiOS key=value log line into a dictionary.
    
    A state machine is used to correctly parse:
    - key="quoted value with spaces and escaped \\" quotes"
    - key=unquoted_value
    - values with embedded '=' or spaces inside quotes
    """
    line = raw_line.strip()
    if not line:
        return {}

    # Strip syslog header prefix if present
    match = SYSLOG_PREFIX_PATTERN.match(line)
    if match:
        line = line[match.end():].lstrip()

    result: Dict[str, str] = {}
    i = 0
    n = len(line)

    while i < n:
        # Skip leading whitespace
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break

        # Read key
        key_start = i
        while i < n and line[i] != '=' and not line[i].isspace():
            i += 1

        if i >= n or line[i] != '=':
            # Token without '=' (e.g. malformed or trailing syslog token), advance
            i += 1
            continue

        key = line[key_start:i].strip()
        i += 1  # Skip '='

        if i >= n:
            result[key] = ""
            break

        # Read value
        if line[i] == '"':
            # Quoted value
            i += 1  # Skip opening quote
            val_chars = []
            while i < n:
                ch = line[i]
                if ch == '\\' and i + 1 < n:
                    next_ch = line[i + 1]
                    if next_ch in ('"', '\\'):
                        val_chars.append(next_ch)
                        i += 2
                        continue
                    else:
                        val_chars.append(ch)
                        i += 1
                        continue
                elif ch == '"':
                    i += 1  # Skip closing quote
                    break
                else:
                    val_chars.append(ch)
                    i += 1
            val = "".join(val_chars)
        else:
            # Unquoted value: terminates on whitespace
            val_start = i
            while i < n and not line[i].isspace():
                i += 1
            val = line[val_start:i]

        result[key] = val

    return result
