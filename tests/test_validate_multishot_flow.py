from __future__ import annotations

import json
from pathlib import Path

from src.sandbox.oracle import OracleResult, Verdict
from src.v2.llm_cli import CLIExecutionResult
from src.v2.storage import ensure_run_layout, write_json
from src.v2.validate import run_validate_multishot


def _base_config() -> dict:
    return {
        "analysis": {
            "model_timeout_seconds": 5,
        },
        "sandbox": {
            "asan_flags": "-fsanitize=address -fno-omit-frame-pointer -g",
            "compiler": "gcc",
        },
        "validation": {
            "verify_runs": 2,
            "strategy": "auto",
            "timeout_seconds": 5,
            "multishot_max_shots": 3,
            "multishot_required_positive": 1,
            "multishot_force_codex_pov_for_asan": True,
            "trigger_prompt_template_path": "src/v2/prompts/codex_trigger_prompt.txt",
            "live_report_name": "multishot_live_report.json",
        },
        "reporting": {
            "json_name": "final_report.json",
            "html_name": "final_report.html",
        },
    }


def _write_minimal_run(
    *,
    run_id: str,
    runs_root: Path,
    target_id: str,
    language: str,
    primary_file: str,
    snapshot_root: Path,
) -> None:
    run_paths = ensure_run_layout(run_id, str(runs_root))
    write_json(
        run_paths["ingest"] / "scan_bundle.json",
        {
            "run_id": run_id,
            "created_at": "2026-01-01T00:00:00+00:00",
            "detect_only": True,
            "targets": [
                {
                    "target_id": target_id,
                    "name": "demo",
                    "snapshot_root": str(snapshot_root),
                    "original_source": str(snapshot_root),
                    "commit": None,
                    "language": language,
                    "scan_mode": "pack",
                    "codeql_db_path": str(runs_root / "unused-db"),
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
                    "target_id": target_id,
                    "snapshot_root": str(snapshot_root),
                    "language_profile": {
                        "codeql_language": language,
                    },
                    "findings_total": 1,
                    "findings_selected": 1,
                    "findings": [
                        {
                            "finding_id": f"{target_id}-finding-0001",
                            "rule_id": "test/rule",
                            "severity": "error",
                            "message": "test finding",
                            "primary_file": primary_file,
                            "primary_line": 1,
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


def test_multishot_command_plan_drives_test_runner(monkeypatch, tmp_path: Path) -> None:
    run_id = "multishot-command"
    target_id = "target-python-01"
    runs_root = tmp_path / "runs"
    snapshot_root = runs_root / run_id / "snapshots" / target_id
    snapshot_root.mkdir(parents=True, exist_ok=True)
    (snapshot_root / "dummy.py").write_text("print('ok')\n", encoding="utf-8")

    _write_minimal_run(
        run_id=run_id,
        runs_root=runs_root,
        target_id=target_id,
        language="python",
        primary_file="dummy.py",
        snapshot_root=snapshot_root,
    )

    captured: dict[str, str | None] = {}
    custom_cmd = "pytest -q tests/test_trigger.py"

    def fake_llm_run(self, model: str, command: str, prompt: str) -> CLIExecutionResult:  # noqa: ARG001
        payload = {
            "should_attempt": True,
            "trigger_kind": "command",
            "command": custom_cmd,
            "pov_stdin": "",
            "expected_signal": "test_failure",
            "confidence": 0.91,
            "rationale": "run a focused failing test",
        }
        return CLIExecutionResult(model="codex", ok=True, returncode=0, stdout=json.dumps(payload), stderr="")

    def fake_oracle_run(
        self,  # noqa: ARG001
        source_file=None,  # noqa: ANN001
        pov_file=None,  # noqa: ANN001
        patch_file=None,  # noqa: ANN001
        extra_files=None,  # noqa: ANN001
        language_profile=None,  # noqa: ANN001
        project_root=None,  # noqa: ANN001
        custom_test_command=None,  # noqa: ANN001
        custom_run_command=None,  # noqa: ANN001
    ) -> OracleResult:
        captured["custom_test_command"] = custom_test_command
        captured["custom_run_command"] = custom_run_command
        return OracleResult(
            verdict=Verdict.TEST_FAILURE,
            exit_code=1,
            stdout="failing test",
            stderr="",
            asan_report="",
        )

    monkeypatch.setattr("src.v2.validate.CLIModelExecutor.run", fake_llm_run)
    monkeypatch.setattr("src.v2.validate.SandboxOracle.run", fake_oracle_run)

    cfg = _base_config()
    json_report, _ = run_validate_multishot(
        run_id=run_id,
        runs_root=str(runs_root),
        config=cfg,
        verify_runs=2,
        strategy="test_runner",
        max_shots=2,
        codex_cli="codex exec -",
    )

    assert captured["custom_test_command"] == custom_cmd
    assert captured["custom_run_command"] is None

    report = json.loads(Path(json_report).read_text(encoding="utf-8"))
    finding = report["targets"][0]["final_findings"][0]
    evidence = finding["validation_evidence"][0]

    assert finding["final_status"] == "confirmed"
    assert evidence["trigger_kind"] == "command"
    assert evidence["trigger_command"] == custom_cmd
    assert evidence["is_positive"] is True


def test_multishot_pov_plan_persists_artifact_for_asan(monkeypatch, tmp_path: Path) -> None:
    run_id = "multishot-asan"
    target_id = "target-cpp-01"
    runs_root = tmp_path / "runs"
    snapshot_root = runs_root / run_id / "snapshots" / target_id
    snapshot_root.mkdir(parents=True, exist_ok=True)
    src_file = snapshot_root / "vuln.c"
    src_file.write_text("int main(){return 0;}\n", encoding="utf-8")

    _write_minimal_run(
        run_id=run_id,
        runs_root=runs_root,
        target_id=target_id,
        language="cpp",
        primary_file="vuln.c",
        snapshot_root=snapshot_root,
    )

    captured: dict[str, str | None] = {}
    pov_text = "AAAA\nBBBB\n"

    def fake_llm_run(self, model: str, command: str, prompt: str) -> CLIExecutionResult:  # noqa: ARG001
        payload = {
            "should_attempt": True,
            "trigger_kind": "pov_stdin",
            "command": "",
            "pov_stdin": pov_text,
            "expected_signal": "asan_crash",
            "confidence": 0.95,
            "rationale": "crafted stdin payload",
        }
        return CLIExecutionResult(model="codex", ok=True, returncode=0, stdout=json.dumps(payload), stderr="")

    def fake_oracle_run(
        self,  # noqa: ARG001
        source_file=None,  # noqa: ANN001
        pov_file=None,  # noqa: ANN001
        patch_file=None,  # noqa: ANN001
        extra_files=None,  # noqa: ANN001
        language_profile=None,  # noqa: ANN001
        project_root=None,  # noqa: ANN001
        custom_test_command=None,  # noqa: ANN001
        custom_run_command=None,  # noqa: ANN001
    ) -> OracleResult:
        captured["source_file"] = str(source_file) if source_file else None
        captured["pov_file"] = str(pov_file) if pov_file else None
        captured["custom_test_command"] = custom_test_command
        captured["custom_run_command"] = custom_run_command
        return OracleResult(
            verdict=Verdict.CRASH,
            exit_code=1,
            stdout="boom",
            stderr="",
            asan_report="AddressSanitizer: stack-buffer-overflow",
        )

    monkeypatch.setattr("src.v2.validate.CLIModelExecutor.run", fake_llm_run)
    monkeypatch.setattr("src.v2.validate.SandboxOracle.run", fake_oracle_run)

    cfg = _base_config()
    json_report, _ = run_validate_multishot(
        run_id=run_id,
        runs_root=str(runs_root),
        config=cfg,
        verify_runs=2,
        strategy="asan",
        max_shots=2,
        codex_cli="codex exec -",
    )

    assert captured["source_file"] == str(src_file.resolve())
    assert captured["custom_test_command"] is None
    assert captured["custom_run_command"] is None

    pov_path = Path(str(captured["pov_file"]))
    assert pov_path.exists()
    assert pov_path.read_text(encoding="utf-8") == pov_text

    report = json.loads(Path(json_report).read_text(encoding="utf-8"))
    finding = report["targets"][0]["final_findings"][0]
    evidence = finding["validation_evidence"][0]

    assert finding["final_status"] == "confirmed"
    assert evidence["trigger_kind"] == "pov_stdin"
    assert evidence["pov_artifact"] == str(pov_path)
    assert evidence["pov_sha256"] != ""
