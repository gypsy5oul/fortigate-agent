#!/usr/bin/env python3
"""Code-reduction accounting for the investigation layer (plan C.3).

Counts the lines under ``src/investigation/`` in four buckets and prints them as Markdown:

* legacy: ``single_call_workflow.py``, ``prompts.py`` and ``prompts/`` (the hand-written single call
  with its packet shrinking and repair loop, and its prompt templates);
* agent runtime: ``agent/*.py`` (ADK agents, tools, callbacks, runtime wrapper, audit, evaluation);
* shared: ``validator.py``, ``eligibility.py``, ``schemas.py`` and the package ``__init__.py`` (used by
  both paths), plus ``src/parsing/redaction.py``, which lives outside the tree but is the same kind
  of shared dependency (reported on its own line, not in the tree total);
* instruction files: ``agent/instructions/*``, counted as configuration, never as code.

For ``.py`` files "code" means a line that is neither blank nor a ``#`` comment (docstrings count as
code). For every other file it means a non-blank line. With ``--patch FILE`` it also reads a unified
diff (``git diff`` output) and prints what that diff removes and adds per bucket, so the reduction
that a change makes can be read before it is applied. Nothing is written; the tree is only read.

    python scripts/code_accounting.py [--root DIR] [--patch FILE] [--json]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

LEGACY = "legacy"
AGENT = "agent runtime"
SHARED = "shared"
INSTRUCTIONS = "instruction files (configuration)"
OTHER = "unclassified under src/investigation/"
BUCKETS = (LEGACY, AGENT, SHARED, INSTRUCTIONS, OTHER)
TREE = "src/investigation"
REDACTION = "src/parsing/redaction.py"
SKIP_DIRS = {"__pycache__", ".adk"}
SHARED_FILES = {"validator.py", "eligibility.py", "schemas.py", "__init__.py"}
LEGACY_FILES = {"single_call_workflow.py", "prompts.py"}
DESCRIPTIONS = {
    LEGACY: "`single_call_workflow.py`, `prompts.py`, `prompts/`",
    AGENT: "`agent/*.py`",
    SHARED: "`validator.py`, `eligibility.py`, `schemas.py`, package `__init__.py`",
    INSTRUCTIONS: "`agent/instructions/*`",
}


def classify(rel_path: str) -> Optional[str]:
    """Bucket of a repository-relative path (posix separators), or None when it is not accounted."""
    if rel_path == REDACTION:
        return SHARED
    if not rel_path.startswith(TREE + "/"):
        return None
    rest = rel_path[len(TREE) + 1:]
    if rest.startswith("agent/instructions/"):
        return INSTRUCTIONS
    if rest.startswith("agent/") and rest.endswith(".py"):
        return AGENT
    if rest in LEGACY_FILES or rest.startswith("prompts/"):
        return LEGACY
    if rest in SHARED_FILES:
        return SHARED
    return OTHER


def count_lines(path: Path) -> Dict[str, int]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    blank = sum(1 for line in lines if not line.strip())
    comment = sum(1 for line in lines if line.strip().startswith("#")) if path.suffix == ".py" else 0
    return {"lines": len(lines), "blank": blank, "comment": comment, "code": len(lines) - blank - comment}


def scan_tree(root: Path) -> List[Dict[str, Any]]:
    """Every file of the accounted trees under ``root`` with its bucket and counts, sorted by path."""
    found: List[Dict[str, Any]] = []
    candidates = []
    tree = root / TREE
    if tree.is_dir():
        for dirpath, dirnames, filenames in os.walk(tree):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                if not name.endswith(".pyc"):
                    candidates.append(Path(dirpath) / name)
    if (root / REDACTION).is_file():
        candidates.append(root / REDACTION)
    for path in candidates:
        rel = path.relative_to(root).as_posix()
        found.append({"path": rel, "bucket": classify(rel), **count_lines(path)})
    return sorted(found, key=lambda f: f["path"])


def parse_patch(text: str) -> List[Dict[str, Any]]:
    """Per-file status and added/removed line counts of a unified diff (``git diff`` output)."""
    files: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    in_hunk = False
    for line in text.splitlines():
        header = re.match(r"diff --git a/(.*) b/(.*)$", line)
        if header:
            current = {"path": header.group(2), "old_path": header.group(1), "status": "modified", "added": 0, "removed": 0}
            files.append(current)
            in_hunk = False
        elif current is None:
            continue
        elif line.startswith("deleted file mode"):
            current["status"], current["path"] = "deleted", current["old_path"]
        elif line.startswith("new file mode"):
            current["status"] = "added"
        elif line.startswith("@@"):
            in_hunk = True
        elif in_hunk and line.startswith("+"):
            current["added"] += 1
        elif in_hunk and line.startswith("-"):
            current["removed"] += 1
    return files


def patch_area(rel_path: str) -> str:
    bucket = classify(rel_path)
    if bucket is not None:
        return bucket
    for prefix, area in (("src/", "src/ outside src/investigation/"), ("tests/", "tests/"), ("docs/", "docs/"), ("scripts/", "scripts/")):
        if rel_path.startswith(prefix):
            return area
    return "config and other"


def summarize(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    buckets = {b: {"files": 0, "lines": 0, "blank": 0, "comment": 0, "code": 0} for b in BUCKETS}
    outside = {"files": 0, "lines": 0, "blank": 0, "comment": 0, "code": 0}
    for f in files:
        target = outside if f["path"] == REDACTION else buckets[f["bucket"]]
        target["files"] += 1
        for key in ("lines", "blank", "comment", "code"):
            target[key] += f[key]
    in_tree = [f for f in files if f["path"] != REDACTION and f["bucket"] != INSTRUCTIONS]
    return {
        "buckets": buckets,
        "redaction_outside_tree": outside,
        "code_total_in_tree": sum(f["code"] for f in in_tree),
        "lines_total_in_tree": sum(f["lines"] for f in in_tree),
        "files_in_tree": len([f for f in files if f["path"] != REDACTION]),
    }


def summarize_patch(files: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    areas: Dict[str, Dict[str, int]] = {}
    for f in files:
        area = areas.setdefault(patch_area(f["path"]), {"deleted_files": 0, "added_files": 0, "modified_files": 0, "removed": 0, "added": 0})
        area[f"{f['status']}_files"] += 1
        area["removed"] += f["removed"]
        area["added"] += f["added"]
    return areas


def render(root: Path, files: List[Dict[str, Any]], stats: Dict[str, Any], patch: Optional[Dict[str, Dict[str, int]]]) -> str:
    b = stats["buckets"]
    out = [
        "## Lines under `src/investigation/`",
        "",
        "| Bucket | Files | Lines | Blank | Comment | Code |",
        "|---|---|---|---|---|---|",
    ]
    for name in (LEGACY, AGENT, SHARED, INSTRUCTIONS):
        row = b[name]
        out.append(f"| {name.capitalize()}: {DESCRIPTIONS[name]} | {row['files']} | {row['lines']} | {row['blank']} | {row['comment']} | {row['code']} |")
    if b[OTHER]["files"]:
        row = b[OTHER]
        out.append(f"| {OTHER} | {row['files']} | {row['lines']} | {row['blank']} | {row['comment']} | {row['code']} |")
    out.append(f"| **Code under `src/investigation/`, instruction files excluded** | {stats['files_in_tree'] - b[INSTRUCTIONS]['files']} | {stats['lines_total_in_tree']} | | | **{stats['code_total_in_tree']}** |")
    red = stats["redaction_outside_tree"]
    out += [
        "",
        f"Shared, outside the tree and not in the total above: `{REDACTION}` ({red['files']} file, {red['lines']} lines, {red['code']} code).",
        "Lines are physical lines; code is a line that is not blank and, in `.py` files, not a `#` comment (docstrings count as code). Instruction files are configuration: they are shown but never added to the code total.",
        "",
        "| File | Bucket | Lines | Code |",
        "|---|---|---|---|",
    ]
    for f in files:
        out.append(f"| `{f['path']}` | {f['bucket']} | {f['lines']} | {f['code']} |")
    if patch is not None:
        out += [
            "",
            "## Effect of the patch (diff lines: removed and added, blanks and comments included)",
            "",
            "| Area | Files deleted | Files added | Files modified | Lines removed | Lines added | Net |",
            "|---|---|---|---|---|---|---|",
        ]
        ordered = [a for a in BUCKETS if a in patch] + sorted(a for a in patch if a not in BUCKETS)
        tree_removed = tree_added = 0
        for area in ordered:
            row = patch[area]
            out.append(
                f"| {area} | {row['deleted_files']} | {row['added_files']} | {row['modified_files']} | "
                f"{row['removed']} | {row['added']} | {row['added'] - row['removed']:+d} |"
            )
            if area in BUCKETS:
                tree_removed += row["removed"]
                tree_added += row["added"]
        out += [
            "",
            f"Under `src/investigation/` (every bucket, instruction files included): {tree_removed} lines removed, {tree_added} added, net {tree_added - tree_removed:+d}.",
        ]
    return "\n".join(out) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Code-reduction accounting for src/investigation/ (plan C.3).")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent), help="repository root to count (default: this checkout)")
    parser.add_argument("--patch", help="a unified diff to account for as well (for example docs/reports/gate-c3-legacy-removal.patch)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    files = scan_tree(root)
    if not files:
        print(f"code_accounting: no {TREE}/ under {root}", file=sys.stderr)
        return 2
    stats = summarize(files)
    patch = None
    if args.patch:
        patch = summarize_patch(parse_patch(Path(args.patch).read_text(encoding="utf-8", errors="replace")))
    if args.json:
        print(json.dumps({"files": files, "summary": stats, "patch": patch}, indent=2, sort_keys=True))
    else:
        print(render(root, files, stats, patch), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
