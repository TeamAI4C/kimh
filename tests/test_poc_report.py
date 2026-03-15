from __future__ import annotations

import json
from pathlib import Path

from src.v2.llm_cli import CLIExecutionResult
from src.v2.poc_report import generate_poc_markdown_reports
from src.v2.storage import append_event, ensure_run_layout, read_json, write_json


def _seed_run(runs_root: Path, run_id: str) -> None:
    run_paths = ensure_run_layout(run_id, str(runs_root))

    write_json(
        run_paths["ingest"] / "scan_bundle.json",
        {
            "run_id": run_id,
            "created_at": "2026-01-01T00:00:00+00:00",
            "detect_only": True,
            "targets": [
                {
                    "target_id": "demo-target-01",
                    "name": "demo",
                    "snapshot_root": "/tmp/snapshot",
                    "original_source": "/tmp/source",
                    "commit": None,
                    "language": "python",
                    "scan_mode": "pack",
                    "codeql_db_path": "/tmp/db",
                    "pov_file": None,
                    "file_index": [],
                }
            ],
        },
    )

    write_json(
        run_paths["analyze"] / "analyze_result.json",
        {
            "run_id": run_id,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "topology": "codex-single-pass",
            "max_rounds": 6,
            "targets": [
                {
                    "target_id": "demo-target-01",
                    "snapshot_root": "/tmp/snapshot",
                    "language_profile": {"codeql_language": "python"},
                    "findings_total_raw": 1,
                    "findings_total": 1,
                    "findings_excluded_by_path": 0,
                    "findings_selected": 1,
                    "findings": [
                        {
                            "finding_id": "demo-target-01-finding-0001",
                            "rule_id": "py/path-injection",
                            "severity": "error",
                            "message": "path traversal candidate",
                            "primary_file": "app.py",
                            "primary_line": 42,
                            "final_decision": "consensus",
                            "consensus_vulnerable": True,
                            "stop_reason": "single-pass accepted",
                            "adjudication_history": [],
                        }
                    ],
                    "model_contribution": {
                        "codex": {"valid_rounds": 1, "consensus_supports": 1},
                        "claude": {"valid_rounds": 0, "consensus_supports": 0},
                    },
                }
            ],
        },
    )

    write_json(
        run_paths["validate"] / "final_report.json",
        {
            "run_id": run_id,
            "generated_at": "2026-01-01T00:00:00+00:00",
            "verify_runs": 2,
            "strategy": "skip",
            "targets": [
                {
                    "target_id": "demo-target-01",
                    "snapshot_root": "/tmp/snapshot",
                    "model_contribution": {
                        "codex": {"valid_rounds": 1, "consensus_supports": 1},
                        "claude": {"valid_rounds": 0, "consensus_supports": 0},
                    },
                    "final_findings": [
                        {
                            "finding_id": "demo-target-01-finding-0001",
                            "rule_id": "py/path-injection",
                            "severity": "error",
                            "message": "path traversal candidate",
                            "primary_file": "app.py",
                            "primary_line": 42,
                            "final_status": "probable",
                            "evidence_score": 0.5,
                            "consensus_vulnerable": True,
                            "adjudication_history": [],
                            "validation_evidence": [
                                {
                                    "run_index": 1,
                                    "verdict": "test_failure",
                                    "exit_code": 1,
                                    "is_positive": True,
                                    "stdout_tail": "traceback",
                                    "stderr_tail": "",
                                    "asan_report": "",
                                    "trigger_kind": "command",
                                    "trigger_command": "pytest -q tests/test_demo.py",
                                    "pov_preview": "",
                                    "pov_artifact": "",
                                    "pov_sha256": "",
                                    "plan_confidence": 0.89,
                                    "plan_rationale": "targeted test",
                                }
                            ],
                            "stop_reason": "single-pass accepted",
                        }
                    ],
                }
            ],
        },
    )

    append_event(
        run_paths["logs"] / "events.jsonl",
        {
            "ts": "2026-01-01T00:00:00+00:00",
            "stage": "validate",
            "event": "multishot_attempt",
            "target_id": "demo-target-01",
            "finding_id": "demo-target-01-finding-0001",
            "shot": 1,
            "verdict": "test_failure",
            "is_positive": True,
        },
    )


def _config() -> dict:
    return {
        "analysis": {"model_timeout_seconds": 5},
        "reporting": {"json_name": "final_report.json", "html_name": "final_report.html"},
        "poc_report": {
            "enabled": True,
            "output_dirname": "poc_reports",
            "prompt_template_path": "src/v2/prompts/codex_poc_report_prompt.txt",
            "timeout_seconds": 5,
            "max_findings": 10,
            "include_statuses": ["confirmed", "probable", "needs-human-review"],
        },
    }


def test_generate_poc_report_uses_codex_output(monkeypatch, tmp_path: Path) -> None:
    run_id = "poc-md-codex"
    runs_root = tmp_path / "runs"
    _seed_run(runs_root, run_id)

    def fake_run(self, model: str, command: str, prompt: str) -> CLIExecutionResult:  # noqa: ARG001
        markdown = (
            "# Path Traversal in app.py leads to file read\n\n"
            "## Summary & Impact\n"
            "User input can escape base dir.\n\n"
            "## Affected Systems\n- demo\n\n"
            "## Steps to Reproduce (STR)\n1. run test\n\n"
            "## Evidence (Proof)\n```text\ntraceback\n```\n\n"
            "## Remediation / Recommendation\nUse path normalization and allowlist.\n"
        )
        return CLIExecutionResult(model="codex", ok=True, returncode=0, stdout=markdown, stderr="")

    monkeypatch.setattr("src.v2.poc_report.CLIModelExecutor.run", fake_run)

    index_path, count = generate_poc_markdown_reports(
        run_id=run_id,
        runs_root=str(runs_root),
        config=_config(),
        codex_cli="codex exec -",
    )

    assert count == 1
    index = read_json(Path(index_path))
    assert len(index["reports"]) == 1
    report_path = Path(index["reports"][0]["report_path"])
    assert report_path.exists()
    assert "Path Traversal" in report_path.read_text(encoding="utf-8")
    assert index["reports"][0]["generator"] == "codex"


def test_generate_poc_report_falls_back_on_codex_failure(monkeypatch, tmp_path: Path) -> None:
    run_id = "poc-md-fallback"
    runs_root = tmp_path / "runs"
    _seed_run(runs_root, run_id)

    def fake_run(self, model: str, command: str, prompt: str) -> CLIExecutionResult:  # noqa: ARG001
        return CLIExecutionResult(
            model="codex",
            ok=False,
            returncode=1,
            stdout="",
            stderr="timeout",
            error="timeout",
        )

    monkeypatch.setattr("src.v2.poc_report.CLIModelExecutor.run", fake_run)

    index_path, count = generate_poc_markdown_reports(
        run_id=run_id,
        runs_root=str(runs_root),
        config=_config(),
        codex_cli="codex exec -",
    )

    assert count == 1
    index = read_json(Path(index_path))
    assert index["reports"][0]["generator"] == "fallback"
    report_path = Path(index["reports"][0]["report_path"])
    body = report_path.read_text(encoding="utf-8")
    assert "## Summary & Impact" in body
    assert "## Steps to Reproduce (STR)" in body
    assert "## Evidence" in body
