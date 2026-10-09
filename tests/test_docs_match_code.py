"""The investigator documentation audited against the code (plan C.3 exit: "docs match code").

Only what a machine can check is checked: the modes and the default of INVESTIGATOR_MODE, the settings,
metrics, files and tests that README.md, docs/runbook.md, docs/adr/005-adk-investigator.md and
docs/data-dictionary.md name. A doc that names something the code does not have fails here, before a
reader trips over it."""

import re
import typing
from pathlib import Path

from prometheus_client import REGISTRY

import src.observability.metrics  # noqa: F401  (registers the metrics)
from config.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
DOC_FILES = ["README.md", "docs/runbook.md", "docs/adr/005-adk-investigator.md", "docs/data-dictionary.md"]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _all_docs() -> str:
    return "\n".join(_read(rel) for rel in DOC_FILES)


def _removed_by_the_legacy_patch():
    """Files the prepared legacy-removal patch deletes and test functions it removes or renames. The docs
    may name them as history, before the patch is applied (they exist) and after (they do not)."""
    patch = ROOT / "docs" / "reports" / "gate-c3-legacy-removal.patch"
    if not patch.exists():
        return set(), set()
    text = patch.read_text(encoding="utf-8", errors="replace")
    files = set(re.findall(r"^diff --git a/(\S+) b/\S+\ndeleted file mode", text, re.M))
    tests = set(re.findall(r"^-(?:async )?def (test_\w+)\(", text, re.M))
    return files, tests


def _section(text: str, start: str, end: str) -> str:
    return text[text.index(start): text.index(end, text.index(start))]


def test_investigator_modes_and_default_in_the_docs_are_those_of_the_setting():
    field = Settings.model_fields["investigator_mode"]
    allowed = set(typing.get_args(field.annotation))
    default = field.default
    assert default in allowed

    section = _section(_read("README.md"), "## 5. Investigator Modes", "## 6. ")
    documented = set(re.findall(r"^\| `([a-z]+)`", section, re.M))  # the modes table: first column, lower case
    assert documented == allowed, f"README section 5 documents {sorted(documented)}, the setting accepts {sorted(allowed)}"
    assert re.search(rf"^\| `INVESTIGATOR_MODE` \| `{default}` \|", section, re.M), "README settings table has another default"

    runbook = _section(_read("docs/runbook.md"), "## 5. Investigator Modes", "### 5.1 ")
    assert all(f"`{mode}`" in runbook for mode in allowed)

    env_value = re.search(r"^INVESTIGATOR_MODE=(\w+)$", _read(".env.example"), re.M).group(1)
    assert env_value in allowed, f".env.example sets INVESTIGATOR_MODE={env_value}"
    assert env_value == default, ".env.example should show the default"


def test_settings_named_in_the_docs_exist():
    names = set(re.findall(
        r"\b(INVESTIGATOR_MODE|AGENT_MAX_LLM_CALLS|AGENT_TIMEOUT_SECONDS|ADK_SESSION_DB_URL|LLM_[A-Z_]*[A-Z]|METRICS_PORT|GCHAT_DRY_RUN)\b",
        _all_docs(),
    ))
    assert {"INVESTIGATOR_MODE", "AGENT_MAX_LLM_CALLS", "AGENT_TIMEOUT_SECONDS"} <= names
    missing = sorted(n for n in names if n.lower() not in Settings.model_fields)
    assert not missing, f"documented settings the code does not have: {missing}"


def test_metrics_named_in_the_docs_are_registered():
    families = {family.name for family in REGISTRY.collect()}
    pattern = r"\bforti_(?:agent|model|jobs|backlog|loki|chat|poller|outbox|incidents|investigations|parser|coverage|unknown)_[a-z0-9_]*"
    text = _all_docs()
    # A wildcard such as forti_agent_shadow_* names a family, not a metric.
    named = {m.group(0).rstrip("_") for m in re.finditer(pattern, text) if text[m.end(): m.end() + 1] != "*"}
    assert {"forti_agent_runs_total", "forti_model_consecutive_failures", "forti_jobs_oldest_pending_seconds"} <= named
    unregistered = sorted(m for m in named if m not in families and re.sub(r"_(total|bucket|sum|count)$", "", m) not in families)
    assert not unregistered, f"documented metrics no code registers: {unregistered}"


def test_files_named_in_the_docs_exist():
    pattern = r"(?<![\w/.])((?:scripts|src|tests|docs|config|evals|dashboards|migrations)/[A-Za-z0-9_./-]*[A-Za-z0-9_]\.(?:py|sh|md|yml|yaml|json|txt|sql|patch))"
    deleted_by_patch, _ = _removed_by_the_legacy_patch()
    missing = []
    for rel in sorted(set(re.findall(pattern, _all_docs()))):
        if re.fullmatch(r"docs/reports/gate-[a-z0-9]+-report\.md", rel):
            continue  # generated from the commit that follows the one it describes
        if rel in deleted_by_patch:
            continue  # history: the removal patch deletes it
        if not (ROOT / rel).exists():
            missing.append(rel)
    assert not missing, f"documented files that do not exist: {missing}"


def test_tests_named_in_the_docs_exist():
    named = set(re.findall(r"(tests/[A-Za-z0-9_/]+\.py)::(test_\w+)", _all_docs()))
    assert named, "the docs name no test"
    _, removed_tests = _removed_by_the_legacy_patch()
    missing = []
    for rel, name in sorted(named):
        if name in removed_tests:
            continue  # history: the removal patch removes or renames it
        path = ROOT / rel
        if not path.exists() or not re.search(rf"^(?:async )?def {name}\(", path.read_text(encoding="utf-8"), re.M):
            missing.append(f"{rel}::{name}")
    assert not missing, f"documented tests that do not exist: {missing}"
