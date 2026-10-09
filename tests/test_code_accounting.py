"""scripts/code_accounting.py (plan C.3): bucket rules, line counting, patch parsing, and that every file
of the real tree is accounted for."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "code_accounting.py"

_spec = importlib.util.spec_from_file_location("code_accounting", SCRIPT)
accounting = importlib.util.module_from_spec(_spec)
sys.modules["code_accounting"] = accounting
_spec.loader.exec_module(accounting)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _tree(root: Path) -> None:
    _write(root, "src/investigation/single_call_workflow.py", "import os\n\n# comment\n\ndef run():\n    return 1\n")
    _write(root, "src/investigation/prompts.py", "X = 1\n")
    _write(root, "src/investigation/prompts/system_v1.txt", "# Version: 1.0.0\nYou are an analyst.\n\n")
    _write(root, "src/investigation/validator.py", "A = 1\nB = 2\n")
    _write(root, "src/investigation/__init__.py", "")
    _write(root, "src/investigation/agent/__init__.py", '"""doc"""\n')
    _write(root, "src/investigation/agent/runtime.py", "a = 1\n# c\nb = 2\n")
    _write(root, "src/investigation/agent/instructions/master.txt", "# Version: 1.1.0\nDo this.\nThen that.\n")
    _write(root, "src/investigation/agent/__pycache__/runtime.cpython-313.pyc", "binary")
    _write(root, "src/investigation/agent/.adk/eval_history/x.json", "{}")
    _write(root, "src/parsing/redaction.py", "R = 1\n\nS = 2\n")
    _write(root, "src/main.py", "not accounted\n")


def test_classify_puts_every_kind_of_file_in_its_bucket():
    c = accounting.classify
    assert c("src/investigation/single_call_workflow.py") == accounting.LEGACY
    assert c("src/investigation/prompts.py") == accounting.LEGACY
    assert c("src/investigation/prompts/user_v1.txt") == accounting.LEGACY
    assert c("src/investigation/agent/runtime.py") == accounting.AGENT
    assert c("src/investigation/agent/__init__.py") == accounting.AGENT
    assert c("src/investigation/agent/instructions/master.txt") == accounting.INSTRUCTIONS
    for shared in ("validator.py", "eligibility.py", "schemas.py", "__init__.py"):
        assert c(f"src/investigation/{shared}") == accounting.SHARED
    assert c("src/parsing/redaction.py") == accounting.SHARED
    assert c("src/investigation/new_module.py") == accounting.OTHER
    assert c("src/main.py") is None


def test_scan_counts_lines_skips_caches_and_keeps_instructions_out_of_the_code_total(tmp_path):
    _tree(tmp_path)
    files = accounting.scan_tree(tmp_path)
    assert {f["path"] for f in files} == {
        "src/investigation/single_call_workflow.py", "src/investigation/prompts.py", "src/investigation/prompts/system_v1.txt",
        "src/investigation/validator.py", "src/investigation/__init__.py", "src/investigation/agent/__init__.py",
        "src/investigation/agent/runtime.py", "src/investigation/agent/instructions/master.txt", "src/parsing/redaction.py",
    }
    by_path = {f["path"]: f for f in files}
    workflow = by_path["src/investigation/single_call_workflow.py"]
    assert (workflow["lines"], workflow["blank"], workflow["comment"], workflow["code"]) == (6, 2, 1, 3)
    prompt = by_path["src/investigation/prompts/system_v1.txt"]
    assert (prompt["lines"], prompt["blank"], prompt["comment"], prompt["code"]) == (3, 1, 0, 2)  # only .py counts '#' as a comment

    stats = accounting.summarize(files)
    assert stats["buckets"][accounting.LEGACY]["files"] == 3 and stats["buckets"][accounting.LEGACY]["code"] == 3 + 1 + 2
    assert stats["buckets"][accounting.AGENT]["code"] == 1 + 2
    assert stats["buckets"][accounting.INSTRUCTIONS]["code"] == 3
    assert stats["redaction_outside_tree"] == {"files": 1, "lines": 3, "blank": 1, "comment": 0, "code": 2}
    # Instruction files and redaction.py are not in the code total of the tree.
    assert stats["code_total_in_tree"] == 3 + 1 + 2 + 2 + 0 + 1 + 2
    assert stats["files_in_tree"] == 8


def test_patch_parsing_counts_deleted_added_and_modified_files_per_area():
    patch = (
        "diff --git a/src/investigation/single_call_workflow.py b/src/investigation/single_call_workflow.py\n"
        "deleted file mode 100644\nindex 111..000\n--- a/src/investigation/single_call_workflow.py\n+++ /dev/null\n"
        "@@ -1,3 +0,0 @@\n-one\n-two\n--- a SQL comment\n"
        "diff --git a/src/main.py b/src/main.py\nindex 1..2 100644\n--- a/src/main.py\n+++ b/src/main.py\n"
        "@@ -1,2 +1,3 @@\n keep\n-old\n+new\n+newer\n\\ No newline at end of file\n"
        "diff --git a/tests/test_new.py b/tests/test_new.py\nnew file mode 100644\n--- /dev/null\n+++ b/tests/test_new.py\n"
        "@@ -0,0 +1,2 @@\n+a\n+b\n"
    )
    files = accounting.parse_patch(patch)
    assert [(f["path"], f["status"], f["removed"], f["added"]) for f in files] == [
        ("src/investigation/single_call_workflow.py", "deleted", 3, 0),
        ("src/main.py", "modified", 1, 2),
        ("tests/test_new.py", "added", 0, 2),
    ]
    areas = accounting.summarize_patch(files)
    assert areas[accounting.LEGACY]["deleted_files"] == 1 and areas[accounting.LEGACY]["removed"] == 3
    assert areas["src/ outside src/investigation/"]["modified_files"] == 1
    assert areas["tests/"]["added_files"] == 1 and areas["tests/"]["added"] == 2


def test_cli_prints_markdown_and_json_for_a_tree_and_a_patch(tmp_path):
    _tree(tmp_path)
    patch = tmp_path / "x.patch"
    patch.write_text(
        "diff --git a/src/investigation/prompts.py b/src/investigation/prompts.py\ndeleted file mode 100644\n"
        "--- a/src/investigation/prompts.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-X = 1\n",
        encoding="utf-8",
    )
    md = subprocess.run([sys.executable, str(SCRIPT), "--root", str(tmp_path), "--patch", str(patch)], capture_output=True, text=True, check=True).stdout
    assert "## Lines under `src/investigation/`" in md and "## Effect of the patch" in md
    assert "Under `src/investigation/` (every bucket, instruction files included): 1 lines removed, 0 added, net -1." in md
    data = json.loads(subprocess.run([sys.executable, str(SCRIPT), "--root", str(tmp_path), "--json"], capture_output=True, text=True, check=True).stdout)
    assert data["summary"]["code_total_in_tree"] == 11 and data["patch"] is None
    empty = subprocess.run([sys.executable, str(SCRIPT), "--root", str(tmp_path / "nowhere")], capture_output=True, text=True)
    assert empty.returncode == 2


def test_every_file_of_the_real_tree_is_accounted_for():
    files = accounting.scan_tree(ROOT)
    assert files, "no src/investigation/ files found"
    assert [f["path"] for f in files if f["bucket"] == accounting.OTHER] == []
    buckets = {f["bucket"] for f in files}
    assert accounting.AGENT in buckets and accounting.SHARED in buckets and accounting.INSTRUCTIONS in buckets
    instruction_files = sorted(Path(f["path"]).name for f in files if f["bucket"] == accounting.INSTRUCTIONS)
    assert instruction_files == ["context.txt", "evidence.txt", "master.txt", "writer.txt"]
