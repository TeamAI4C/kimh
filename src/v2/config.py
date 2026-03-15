from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG: dict[str, Any] = {
    "sync": {
        "runs_root": ".findvuln/runs",
    },
    "analysis": {
        "topology": "parallel-adjudicated",
        "max_rounds": 6,
        "min_consensus_confidence": 0.60,
        "require_evidence": True,
        "max_consecutive_failures": 2,
        "model_timeout_seconds": 300,
        "prompt_template_path": "src/v2/prompts/codex_default_prompt.txt",
        "codex_ql": {
            "enabled": True,
            "max_queries": 6,
            "max_retries": 2,
            "timeout_seconds": 0,
            "prompt_template_path": "src/v2/prompts/codex_ql_query_prompt.txt",
        },
        "exclude_primary_path_globs": [
            "test/**",
            "tests/**",
            "**/test/**",
            "**/tests/**",
            "**/testing/**",
            "**/*_test.py",
            "**/test_*.py",
        ],
    },
    "llm": {
        "codex_cli": "codex exec --model gpt-5.3-codex -c 'reasoning_effort=\"xhigh\"' --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -",
        "claude_cli": "claude",
    },
    "validation": {
        "verify_runs": 2,
        "strategy": "auto",
        "execution_owner": "codex-host",
        "multishot_max_shots": 6,
        "multishot_required_positive": 2,
        "trigger_prompt_template_path": "src/v2/prompts/codex_trigger_prompt.txt",
        "live_report_name": "multishot_live_report.json",
    },
    "reporting": {
        "json_name": "final_report.json",
        "html_name": "final_report.html",
    },
    "poc_report": {
        "enabled": False,
        "output_dirname": "poc_reports",
        "prompt_template_path": "src/v2/prompts/codex_poc_report_prompt.txt",
        "timeout_seconds": 300,
        "max_findings": 50,
        "include_statuses": ["confirmed", "probable"],
    },
}


def _merge(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _merge(dst[key], value)
        else:
            dst[key] = value
    return dst


def load_config(config_path: str = "config/settings.yaml") -> dict[str, Any]:
    merged = deepcopy(DEFAULT_CONFIG)
    cfg_path = Path(config_path)
    if not cfg_path.exists():
        return merged

    with open(cfg_path) as f:
        loaded = yaml.safe_load(f) or {}

    if not isinstance(loaded, dict):
        return merged

    _merge(merged, loaded)
    return merged
