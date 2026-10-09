"""C2.2 lab evaluation: the golden set (and any exported lab incidents) through ADK's AgentEvaluator
against the model named by LLM_BASE_URL / LLM_MODEL. Marked ``lab`` and skipped unless
RUN_LAB_EVALS=1; CI runs only the scripted-model tests. Needs ``google-adk[eval]`` (not in the
runtime requirements).

    RUN_LAB_EVALS=1 LLM_BASE_URL=http://<vllm-host>:8000/v1 LLM_MODEL=<served-model> \\
      pytest -m lab -v tests/agent/test_golden_eval_lab.py

The criteria are evals/test_config.json. ``AgentEvaluator.evaluate`` only reads a test_config.json
placed beside each test file, so this calls ``AgentEvaluator.evaluate_eval_set`` (which ``evaluate``
calls per file) with that one config. LAB_EVAL_RUNS sets the runs per case (default 2).
"""

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EVAL_FILES = sorted((ROOT / "evals" / "golden").glob("*.test.json")) + sorted((ROOT / "evals" / "lab").glob("*.test.json"))

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(os.getenv("RUN_LAB_EVALS") != "1", reason="lab evaluation: set RUN_LAB_EVALS=1 and point LLM_BASE_URL at the lab model"),
    # The evaluated App (and its model client) is built once per process: one event loop for all cases.
    pytest.mark.asyncio(loop_scope="module"),
]


@pytest.mark.parametrize("eval_file", EVAL_FILES, ids=[p.name for p in EVAL_FILES])
async def test_golden_case_meets_the_c2_2_criteria(eval_file):
    pytest.importorskip("google.adk")
    from google.adk.evaluation.agent_evaluator import AgentEvaluator
    from google.adk.evaluation.eval_config import EvalConfig
    from google.adk.evaluation.eval_set import EvalSet

    config = EvalConfig.model_validate_json((ROOT / "evals" / "test_config.json").read_text(encoding="utf-8"))
    eval_set = EvalSet.model_validate_json(eval_file.read_text(encoding="utf-8"))
    await AgentEvaluator.evaluate_eval_set(
        agent_module="src.investigation.agent",
        eval_set=eval_set,
        eval_config=config,
        num_runs=int(os.getenv("LAB_EVAL_RUNS", "2")),
        print_detailed_results=True,
    )
