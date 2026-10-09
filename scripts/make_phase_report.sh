#!/usr/bin/env bash
# Generate a phase verification report from a clean checkout of HEAD.
#
# Every transcript in the report comes from commands run inside a detached git
# worktree of the exact commit named at the top, so the report cannot describe a
# tree other than the one pushed. Nothing is typed by hand except the optional
# notes file, which is included verbatim under its own heading.
#
# Usage:
#   TEST_DATABASE_URL=postgresql://... scripts/make_phase_report.sh <phase> <output.md> [notes.md]
#
# Environment:
#   TEST_DATABASE_URL  scratch PostgreSQL 16 database for the suite (required)
#   PYTHON             interpreter with the dev requirements installed (default: python3)
#   EVAL_PYTHON        optional interpreter that also has google-adk[eval]: the golden set is then run
#                      with `adk eval` against the scripted fake vLLM and the result is included
#   SKIP_DOCKER=1      do not attempt the container build even if a daemon is available
#
# Tests may write Markdown files to $PHASE_REPORT_ARTIFACTS during the suite run (for example the
# shadow comparison harness output of the offline shadow run); each is included verbatim.
set -euo pipefail

PHASE="${1:?usage: make_phase_report.sh <phase> <output.md> [notes.md]}"
OUT="${2:?usage: make_phase_report.sh <phase> <output.md> [notes.md]}"
NOTES="${3:-}"
: "${TEST_DATABASE_URL:?TEST_DATABASE_URL must point at a scratch PostgreSQL 16 database}"
PYTHON="${PYTHON:-python3}"
# Interpreter directory, masked in transcripts (pytest prints it in its header line).
case "$PYTHON" in */*) PYTHON_DIR="$(cd "$(dirname "$PYTHON")" && pwd)" ;; *) PYTHON_DIR="/nonexistent-python-dir" ;; esac
# Interpreter prefix (site-packages paths in warnings), masked as well.
PYTHON_PREFIX="$("$PYTHON" -c 'import sys; print(sys.prefix)' 2>/dev/null || echo /nonexistent-python-prefix)"
EVAL_PYTHON="${EVAL_PYTHON:-}"
EVAL_PREFIX="/nonexistent-eval-prefix"
[ -n "$EVAL_PYTHON" ] && EVAL_PREFIX="$("$EVAL_PYTHON" -c 'import sys; print(sys.prefix)')"

REPO_ROOT="$(git rev-parse --show-toplevel)"
HEAD_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
SHORT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
DIRTY="$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no || true)"
OUT_ABS="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
[ -n "$NOTES" ] && NOTES="$(cd "$(dirname "$NOTES")" && pwd)/$(basename "$NOTES")"

WORK="$(mktemp -d)"
CHECKOUT="$WORK/checkout"
FAKE_PID=""
cleanup() {
  [ -n "$FAKE_PID" ] && kill "$FAKE_PID" >/dev/null 2>&1 || true
  git -C "$REPO_ROOT" worktree remove --force "$CHECKOUT" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

git -C "$REPO_ROOT" worktree add --detach "$CHECKOUT" "$HEAD_SHA" >/dev/null 2>&1
cd "$CHECKOUT"

# Paths and private addresses never reach the report: the checkout and repo paths are
# replaced, database URLs are redacted, and RFC 1918 addresses are masked. The
# documentation ranges used by the test fixtures (198.51.100.0/24, 203.0.113.0/24) and
# loopback are kept because they are not site information.
redact() {
  sed -E \
    -e "s#$CHECKOUT#<checkout>#g" \
    -e "s#$REPO_ROOT#<repo>#g" \
    -e "s#${PYTHON_DIR}#<python-bin>#g" \
    -e "s#${PYTHON_PREFIX}#<python-prefix>#g" \
    -e "s#${EVAL_PREFIX}#<eval-python-prefix>#g" \
    -e "s#(postgres(ql)?://)[^[:space:]'\"]+#\1<redacted>#g" \
    -e "s#\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b#<private-ip>#g" \
    -e "s#\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b#<private-ip>#g" \
    -e "s#\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b#<private-ip>#g"
}

PY_VERSION="$("$PYTHON" -c 'import sys; print(sys.version.split()[0])')"
PYTEST_VERSION="$("$PYTHON" -c 'import pytest; print(pytest.__version__)')"
PG_VERSION="$("$PYTHON" - <<'PYEOF' 2>/dev/null || echo "unknown"
import asyncio, os, asyncpg
async def main():
    c = await asyncpg.connect(os.environ["TEST_DATABASE_URL"])
    print((await c.fetchval("SHOW server_version")))
    await c.close()
asyncio.run(main())
PYEOF
)"

# ---- test suite (full listing, so every test id in the report exists at this commit) ----
SUITE_LOG="$WORK/suite.log"
ARTIFACTS="$WORK/artifacts"
mkdir -p "$ARTIFACTS"
set +e
GCHAT_DRY_RUN=true PHASE_REPORT_ARTIFACTS="$ARTIFACTS" "$PYTHON" -m pytest -v -p no:cacheprovider -o log_cli=false --tb=short \
  --junitxml="$WORK/junit.xml" tests/ >"$SUITE_LOG" 2>&1
SUITE_STATUS=$?
set -e
SUITE_SUMMARY="$(grep -E '^(=+ .*(passed|failed|error).* =+)$' "$SUITE_LOG" | tail -1 | sed -E 's/^=+ //; s/ =+$//')"
COLLECTED="$("$PYTHON" -m pytest --collect-only -q -p no:cacheprovider tests/ 2>/dev/null | grep -cE '::' || true)"

# ---- offline adk eval of the golden set against the scripted fake vLLM (only with EVAL_PYTHON) ----
EVAL_LOG="$WORK/adk_eval.log"
EVAL_STATUS="SKIPPED"
if [ -n "$EVAL_PYTHON" ]; then
  FAKE_PORT="$("$PYTHON" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
  "$PYTHON" -c "import sys, uvicorn; sys.path.insert(0, '.'); from tests.e2e.fake_endpoints import app; uvicorn.run(app, host='127.0.0.1', port=${FAKE_PORT}, log_level='warning')" \
    >"$WORK/fake_vllm.log" 2>&1 &
  FAKE_PID=$!
  "$PYTHON" -c "
import time, urllib.request
for _ in range(100):
    try:
        urllib.request.urlopen('http://127.0.0.1:${FAKE_PORT}/capture', timeout=1); break
    except Exception:
        time.sleep(0.1)
"
  set +e
  PYTHONPATH=. LLM_BASE_URL="http://127.0.0.1:${FAKE_PORT}/v1" LLM_MODEL=scripted-fake \
    "$EVAL_PYTHON" -m google.adk.cli eval src/investigation/agent evals/golden/*.test.json \
    --config_file_path evals/test_config.json >"$WORK/adk_eval_raw.log" 2>&1
  EVAL_RC=$?
  set -e
  kill "$FAKE_PID" >/dev/null 2>&1 || true
  FAKE_PID=""
  {
    echo "\$ PYTHONPATH=. LLM_BASE_URL=http://127.0.0.1:<port>/v1 LLM_MODEL=scripted-fake python -m google.adk.cli eval src/investigation/agent evals/golden/*.test.json --config_file_path evals/test_config.json"
    echo "exit status: ${EVAL_RC}"
    "$EVAL_PYTHON" -c 'import importlib.metadata as m; print("google-adk " + m.version("google-adk") + ", google-cloud-aiplatform " + m.version("google-cloud-aiplatform") + " (eval extras)")'
    echo
    sed -n '/^Eval Run Summary/,$p' "$WORK/adk_eval_raw.log"
    echo
    echo "Per case, from the eval results adk eval wrote (src/investigation/agent/.adk/eval_history):"
    "$EVAL_PYTHON" - <<'PYEOF'
import glob, json
from google.adk.evaluation.evaluator import EvalStatus
print(f"{'case':32} {'overall':8} {'tool_trajectory_avg_score':>26} {'response_match_score':>21}")
passed = total = 0
for path in sorted(glob.glob("src/investigation/agent/.adk/eval_history/*.evalset_result.json")):
    for case in json.load(open(path, encoding="utf-8"))["eval_case_results"]:
        m = {r["metric_name"]: r for r in case["overall_eval_metric_results"]}
        def cell(name):
            r = m.get(name) or {}
            return f"{r.get('score', float('nan')):.3f} {EvalStatus(r['eval_status']).name}" if r else "n/a"
        overall = EvalStatus(case["final_eval_status"]).name
        total += 1
        passed += overall == "PASSED"
        print(f"{case['eval_id']:32} {overall:8} {cell('tool_trajectory_avg_score'):>26} {cell('response_match_score'):>21}")
print(f"cases passing every criterion: {passed} of {total}")
PYEOF
  } >"$EVAL_LOG" 2>&1
  EVAL_STATUS="ran (exit ${EVAL_RC}); $(grep -E '^cases passing every criterion' "$EVAL_LOG" || echo 'no per-case results')"
else
  echo "SKIPPED: set EVAL_PYTHON to an interpreter with google-adk[eval] to run the golden set with adk eval." >"$EVAL_LOG"
fi

# ---- container build (only when a daemon is reachable) ----
DOCKER_LOG="$WORK/docker.log"
DOCKER_STATUS="SKIPPED"
if [ "${SKIP_DOCKER:-0}" != "1" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  set +e
  docker build -t forti-intel-agent:report . >"$DOCKER_LOG" 2>&1
  rc=$?
  set -e
  if [ $rc -eq 0 ]; then DOCKER_STATUS="PASSED"; else DOCKER_STATUS="FAILED (exit $rc)"; fi
else
  echo "SKIPPED: no Docker daemon reachable from this host (or SKIP_DOCKER=1)." >"$DOCKER_LOG"
fi

# ---- version manifest: what is pinned vs what the interpreter actually has ----
MANIFEST="$WORK/manifest.txt"
{
  printf '%-20s %-14s %s\n' "package" "pinned" "installed"
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    name="${line%%==*}"; pin="${line#*==}"; name="${name%%\[*}"  # pip show takes no extras
    inst="$("$PYTHON" -m pip show "$name" 2>/dev/null | awk '/^Version:/{print $2}')"
    printf '%-20s %-14s %s\n' "$name" "$pin" "${inst:-missing}"
  done < requirements.in
} >"$MANIFEST"

# ---- assemble ----
{
  echo "# ${PHASE} verification report"
  echo
  echo "Generated by \`scripts/make_phase_report.sh\` from a detached worktree of the commit below. All transcripts are command output from that worktree; nothing below the notes section is hand-written."
  echo
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Commit | \`${HEAD_SHA}\` (\`${SHORT_SHA}\`) |"
  echo "| Branch | \`${BRANCH}\` |"
  echo "| Generated (UTC) | $(date -u +%Y-%m-%dT%H:%M:%SZ) |"
  echo "| Working tree at generation | $([ -z "$DIRTY" ] && echo clean || echo "**DIRTY: uncommitted changes in tracked files; the report describes HEAD, not the working tree**") |"
  echo "| Python | ${PY_VERSION} |"
  echo "| pytest | ${PYTEST_VERSION} |"
  echo "| PostgreSQL | ${PG_VERSION} |"
  echo "| Kernel | $(uname -sr) |"
  echo "| Tests collected | ${COLLECTED} |"
  echo "| Suite result | ${SUITE_SUMMARY:-see transcript} (exit ${SUITE_STATUS}) |"
  echo "| Offline adk eval | ${EVAL_STATUS} |"
  echo "| Container build | ${DOCKER_STATUS} |"
  echo
  if [ -n "$NOTES" ] && [ -f "$NOTES" ]; then
    echo "## Notes (hand-written, supplied as \`$(basename "$NOTES")\`)"
    echo
    cat "$NOTES"
    echo
  fi
  echo "## Version manifest"
  echo
  echo '```'
  cat "$MANIFEST"
  echo '```'
  echo
  for artifact in "$ARTIFACTS"/*.md; do
    [ -f "$artifact" ] || continue
    echo "## Written by the suite: \`$(basename "$artifact")\`"
    echo
    sed -E 's/^(#+) /\1## /' "$artifact"
    echo
  done
  echo "## Offline adk eval of the golden set (scripted fake vLLM)"
  echo
  echo '```'
  cat "$EVAL_LOG"
  echo '```'
  echo
  echo "## Test suite transcript"
  echo
  echo "Command: \`GCHAT_DRY_RUN=true ${PYTHON##*/} -m pytest -v -p no:cacheprovider -o log_cli=false --tb=short tests/\` with \`TEST_DATABASE_URL\` set."
  echo
  echo '```'
  cat "$SUITE_LOG"
  echo '```'
  echo
  echo "## Container build transcript"
  echo
  echo '```'
  tail -n 60 "$DOCKER_LOG"
  echo '```'
} | redact >"$OUT_ABS"

# The report itself must not carry site information.
if grep -nE '\b10\.[0-9]+\.[0-9]+\.[0-9]+\b|\b192\.168\.|\b172\.(1[6-9]|2[0-9]|3[01])\.|password=' "$OUT_ABS" >/dev/null; then
  echo "ERROR: generated report still contains a private address or credential; refusing to keep it" >&2
  rm -f "$OUT_ABS"
  exit 2
fi

echo "Report written to $OUT_ABS (suite exit ${SUITE_STATUS}, build ${DOCKER_STATUS})"
exit "$SUITE_STATUS"
