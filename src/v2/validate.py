from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.lang_detect import get_profile
from src.sandbox.oracle import OracleResult, SandboxOracle, Verdict
from src.v2.contracts import (
    AdjudicationRecord,
    FinalFinding,
    FinalStatus,
    ValidationEvidence,
    ValidationResult,
    ValidateTargetResult,
)
from src.v2.llm_cli import CLIModelExecutor, TriggerPlan, parse_trigger_plan
from src.v2.reporting import write_validation_reports
from src.v2.storage import append_event, ensure_run_layout, read_json, write_json

_TECHNICAL_VERDICTS = {
    "timeout",
    "unknown",
    "compile_error",
    "patch_error",
    "codex_error",
    "codex_parse_error",
    "codex_no_pov_plan",
    "host_prepare_error",
    "host_verify_error",
}

def _require_non_skip_strategy(strategy: str) -> None:
    if strategy == "skip":
        raise RuntimeError("Validation strategy 'skip' is not allowed for V2 real verification runs.")


def _has_runtime_evidence(evidences: list[ValidationEvidence]) -> bool:
    return any(ev.executed for ev in evidences)


def _contains_signal(text: str, expected_signal: str) -> bool:
    if not expected_signal:
        return False
    return expected_signal.lower() in text.lower()


def _run_host_command(command: str, cwd: str, timeout_seconds: int) -> tuple[int, str, str, str]:
    """Run a host command through bash and return (exit, stdout, stderr, error-kind)."""
    try:
        proc = subprocess.run(
            ["bash", "-lc", command],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return int(proc.returncode), proc.stdout or "", proc.stderr or "", ""
    except subprocess.TimeoutExpired as exc:
        return -1, exc.stdout or "", exc.stderr or "", "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return -1, "", str(exc), "error"


def _to_adjudication_record(raw: dict[str, Any]) -> AdjudicationRecord:
    from src.v2.contracts import AdjudicationDecision
    from src.v2.contracts import EvidenceLocation, ModelVerdict

    def _to_verdict(data: dict[str, Any] | None) -> ModelVerdict | None:
        if data is None:
            return None
        ev = [
            EvidenceLocation(
                file=str(x.get("file", "")),
                line=int(x.get("line", 0)),
                reason=str(x.get("reason", "")),
            )
            for x in data.get("evidence_locations", [])
            if isinstance(x, dict)
        ]
        return ModelVerdict(
            model=str(data.get("model", "")),
            is_vulnerable=bool(data.get("is_vulnerable", False)),
            summary=str(data.get("summary", "")),
            evidence_locations=ev,
            cwe_id=str(data["cwe_id"]) if data.get("cwe_id") else None,
            cvss_estimate=float(data["cvss_estimate"]) if data.get("cvss_estimate") is not None else None,
            reproduction_hypothesis=str(data.get("reproduction_hypothesis", "")),
            confidence=float(data.get("confidence", 0.0)),
            raw_output=str(data.get("raw_output", "")),
        )

    return AdjudicationRecord(
        round_index=int(raw.get("round_index", 0)),
        decision=AdjudicationDecision(str(raw.get("decision", "dispute"))),
        reason=str(raw.get("reason", "")),
        evidence_sufficient=bool(raw.get("evidence_sufficient", False)),
        consensus_vulnerable=raw.get("consensus_vulnerable"),
        consensus_confidence=float(raw.get("consensus_confidence", 0.0)),
        codex=_to_verdict(raw.get("codex")),
        claude=_to_verdict(raw.get("claude")),
    )


def _is_positive_evidence(result: OracleResult, strategy: str) -> bool:
    if strategy == "asan":
        return result.verdict == Verdict.CRASH
    if strategy in ("test_runner", "build_and_test"):
        return result.verdict == Verdict.TEST_FAILURE
    return False


def resolve_final_status(
    *,
    final_decision: str,
    consensus_vulnerable: bool | None,
    evidences: list[ValidationEvidence],
    verify_runs: int,
) -> FinalStatus:
    if final_decision != "consensus":
        return FinalStatus.NEEDS_HUMAN_REVIEW

    if consensus_vulnerable is False:
        return FinalStatus.REJECTED

    if consensus_vulnerable is None:
        return FinalStatus.NEEDS_HUMAN_REVIEW

    positives = sum(1 for e in evidences if e.is_positive)
    if positives == verify_runs:
        return FinalStatus.CONFIRMED
    if positives > 0:
        return FinalStatus.PROBABLE

    technical = sum(1 for e in evidences if e.verdict in _TECHNICAL_VERDICTS)
    if technical > 0:
        return FinalStatus.NEEDS_HUMAN_REVIEW
    return FinalStatus.REJECTED


def _resolve_multishot_status(
    *,
    consensus_vulnerable: bool | None,
    evidences: list[ValidationEvidence],
    required_positive: int,
) -> FinalStatus:
    if consensus_vulnerable is False:
        return FinalStatus.REJECTED
    if consensus_vulnerable is None:
        return FinalStatus.NEEDS_HUMAN_REVIEW

    positives = sum(1 for e in evidences if e.is_positive)
    if positives >= required_positive:
        return FinalStatus.CONFIRMED
    if positives > 0:
        return FinalStatus.PROBABLE

    if not evidences:
        return FinalStatus.NEEDS_HUMAN_REVIEW

    technical = any(e.verdict in _TECHNICAL_VERDICTS for e in evidences)
    if technical:
        return FinalStatus.NEEDS_HUMAN_REVIEW
    return FinalStatus.REJECTED


def _build_trigger_prompt(
    *,
    template: str,
    finding: dict[str, Any],
    target_id: str,
    language: str,
    snapshot_root: str,
    shot_index: int,
    attempts: list[dict[str, Any]],
    skill_references: list[str],
) -> str:
    schema = {
        "should_attempt": "boolean",
        "execution_target": "one of: host_docker | ''",
        "prepare_commands": ["string"],
        "verify_command": "string",
        "trigger_kind": "one of: none | command | pov_stdin (oracle mode compatibility)",
        "command": "string",
        "pov_stdin": "string",
        "expected_signal": "string (required for codex-host execution)",
        "confidence": "number(0.0~1.0)",
        "rationale": "string",
    }

    rendered = template
    rendered = rendered.replace("{{SKILL_REFERENCES}}", "\n".join(f"- {x}" for x in skill_references))
    rendered = rendered.replace("{{SCHEMA_JSON}}", json.dumps(schema, indent=2))
    rendered = rendered.replace("{{SHOT_INDEX}}", str(shot_index))
    rendered = rendered.replace("{{TARGET_ID}}", target_id)
    rendered = rendered.replace("{{LANGUAGE}}", language)
    rendered = rendered.replace("{{SNAPSHOT_ROOT}}", snapshot_root)
    rendered = rendered.replace("{{FINDING_JSON}}", json.dumps(finding, indent=2))
    rendered = rendered.replace("{{ATTEMPT_HISTORY_JSON}}", json.dumps(attempts, indent=2))
    return rendered


def _attempt_stub(e: ValidationEvidence) -> dict[str, Any]:
    return {
        "shot": e.run_index,
        "verdict": e.verdict,
        "is_positive": e.is_positive,
        "executed": e.executed,
        "execution_owner": e.execution_owner,
        "execution_target": e.execution_target,
        "prepare_commands": e.prepare_commands,
        "verify_command": e.verify_command,
        "expected_signal": e.expected_signal,
        "signal_matched": e.signal_matched,
        "plan_confidence": e.plan_confidence,
        "trigger_kind": e.trigger_kind,
        "trigger_command": e.trigger_command,
        "pov_preview": e.pov_preview,
        "pov_artifact": e.pov_artifact,
        "pov_sha256": e.pov_sha256,
    }


def _oracle_unknown(reason: str) -> OracleResult:
    return OracleResult(
        verdict=Verdict.UNKNOWN,
        exit_code=-1,
        stdout="",
        stderr=reason,
        asan_report="",
    )


def _persist_pov_artifact(
    *,
    validate_dir: Path,
    target_id: str,
    finding_id: str,
    shot: int,
    pov_text: str,
) -> tuple[str, str]:
    pov_dir = validate_dir / "pov_artifacts" / target_id / finding_id
    pov_dir.mkdir(parents=True, exist_ok=True)
    pov_path = pov_dir / f"shot-{shot:02d}.txt"
    pov_path.write_text(pov_text, encoding="utf-8")
    digest = hashlib.sha256(pov_text.encode("utf-8")).hexdigest()
    return str(pov_path), digest


def run_validate(
    *,
    run_id: str,
    runs_root: str,
    config: dict[str, Any],
    verify_runs: int,
    strategy: str,
    execution_owner: str,
) -> tuple[str, str]:
    run_paths = ensure_run_layout(run_id, runs_root)
    events_path = run_paths["logs"] / "events.jsonl"

    analyze_path = run_paths["analyze"] / "analyze_result.json"
    if not analyze_path.exists():
        raise RuntimeError(f"Analyze result not found: {analyze_path}")

    bundle = read_json(run_paths["ingest"] / "scan_bundle.json")
    bundle_targets = {str(t["target_id"]): t for t in bundle.get("targets", [])}

    analyze = read_json(analyze_path)
    target_results: list[ValidateTargetResult] = []

    validation_cfg = config.get("validation", {})
    chosen_strategy = strategy if strategy != "auto" else validation_cfg.get("strategy", "auto")
    _require_non_skip_strategy(str(chosen_strategy))

    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "validate",
            "event": "start",
            "run_id": run_id,
            "verify_runs": verify_runs,
            "strategy": chosen_strategy,
            "mode": "single-shot",
            "execution_owner": execution_owner,
        },
    )

    missing_runtime_evidence: list[str] = []
    for t in analyze.get("targets", []):
        target_id = str(t["target_id"])
        target_bundle = bundle_targets.get(target_id)
        if not target_bundle:
            continue

        profile = get_profile(str(t["language_profile"]["codeql_language"]))
        oracle = SandboxOracle(
            timeout=int(validation_cfg.get("timeout_seconds", 120)),
            asan_flags=str(config.get("sandbox", {}).get("asan_flags", "-fsanitize=address -fno-omit-frame-pointer -g")),
            compiler=str(config.get("sandbox", {}).get("compiler", "gcc")),
            verification_strategy=chosen_strategy,
        )

        finals: list[FinalFinding] = []
        for finding in t.get("findings", []):
            adjudication_history = [_to_adjudication_record(x) for x in finding.get("adjudication_history", [])]

            evidences: list[ValidationEvidence] = []
            if finding.get("final_decision") == "consensus" and finding.get("consensus_vulnerable") is True:
                primary_file = str(finding.get("primary_file", ""))
                source_abs = None
                if primary_file:
                    source_abs = str((run_paths["snapshots"] / target_id / primary_file).resolve())

                if profile.sandbox_strategy != "asan" or source_abs:
                    for run_idx in range(1, verify_runs + 1):
                        oracle_result = oracle.run(
                            source_file=source_abs if profile.sandbox_strategy == "asan" else None,
                            pov_file=target_bundle.get("pov_file"),
                            patch_file=None,
                            language_profile=profile,
                            project_root=t.get("snapshot_root"),
                        )
                        is_positive = _is_positive_evidence(oracle_result, profile.sandbox_strategy)
                        evidences.append(
                            ValidationEvidence(
                                run_index=run_idx,
                                verdict=oracle_result.verdict.value,
                                exit_code=int(oracle_result.exit_code),
                                is_positive=is_positive,
                                executed=True,
                                execution_owner="oracle",
                                execution_target="oracle_sandbox",
                                stdout_tail=oracle_result.stdout[-2000:] if oracle_result.stdout else "",
                                stderr_tail=oracle_result.stderr[-2000:] if oracle_result.stderr else "",
                                asan_report=oracle_result.asan_report,
                            )
                        )
                else:
                    evidences.append(
                        ValidationEvidence(
                            run_index=1,
                            verdict="unknown",
                            exit_code=-1,
                            is_positive=False,
                            executed=False,
                            execution_owner="oracle",
                            execution_target="oracle_sandbox",
                            stderr_tail="ASAN validation requires source_file but no location was provided.",
                        )
                    )

            if finding.get("final_decision") == "consensus" and finding.get("consensus_vulnerable") is True:
                if not _has_runtime_evidence(evidences):
                    missing_runtime_evidence.append(str(finding.get("finding_id")))
                    append_event(
                        events_path,
                        {
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "stage": "validate",
                            "event": "runtime_evidence_missing",
                            "target_id": target_id,
                            "finding_id": str(finding.get("finding_id")),
                        },
                    )

            status = resolve_final_status(
                final_decision=str(finding.get("final_decision", "needs-human-review")),
                consensus_vulnerable=finding.get("consensus_vulnerable"),
                evidences=evidences,
                verify_runs=verify_runs,
            )

            evidence_score = 0.0
            if evidences:
                evidence_score = sum(1 for e in evidences if e.is_positive) / float(len(evidences))

            final = FinalFinding(
                finding_id=str(finding.get("finding_id")),
                rule_id=str(finding.get("rule_id", "unknown")),
                severity=str(finding.get("severity", "error")),
                message=str(finding.get("message", "")),
                primary_file=str(finding.get("primary_file", "")),
                primary_line=int(finding.get("primary_line", 0)),
                final_status=status,
                evidence_score=evidence_score,
                consensus_vulnerable=finding.get("consensus_vulnerable"),
                adjudication_history=adjudication_history,
                validation_evidence=evidences,
                stop_reason=str(finding.get("stop_reason", "")),
            )
            finals.append(final)

            append_event(
                events_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "stage": "validate",
                    "event": "finding_validated",
                    "target_id": target_id,
                    "finding_id": final.finding_id,
                    "status": final.final_status.value,
                    "evidence_score": final.evidence_score,
                },
            )

        target_results.append(
            ValidateTargetResult(
                target_id=target_id,
                snapshot_root=str(t.get("snapshot_root", "")),
                final_findings=finals,
                model_contribution=t.get("model_contribution", {}),
            )
        )

    result = ValidationResult(
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        verify_runs=verify_runs,
        strategy=chosen_strategy,
        targets=target_results,
    )

    reporting_cfg = config.get("reporting", {})
    json_path, html_path = write_validation_reports(
        result=result,
        output_dir=run_paths["validate"],
        json_name=str(reporting_cfg.get("json_name", "final_report.json")),
        html_name=str(reporting_cfg.get("html_name", "final_report.html")),
    )

    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "validate",
            "event": "complete",
            "json_report": str(json_path),
            "html_report": str(html_path),
        },
    )

    if missing_runtime_evidence:
        raise RuntimeError(
            "Runtime evidence missing for consensus-vulnerable findings: "
            + ", ".join(missing_runtime_evidence[:20])
        )

    return str(json_path), str(html_path)


def run_validate_multishot(
    *,
    run_id: str,
    runs_root: str,
    config: dict[str, Any],
    verify_runs: int,
    strategy: str,
    max_shots: int,
    codex_cli: str,
    execution_owner: str,
) -> tuple[str, str]:
    run_paths = ensure_run_layout(run_id, runs_root)
    events_path = run_paths["logs"] / "events.jsonl"

    analyze_path = run_paths["analyze"] / "analyze_result.json"
    if not analyze_path.exists():
        raise RuntimeError(f"Analyze result not found: {analyze_path}")

    bundle = read_json(run_paths["ingest"] / "scan_bundle.json")
    bundle_targets = {str(t["target_id"]): t for t in bundle.get("targets", [])}
    analyze = read_json(analyze_path)

    validation_cfg = config.get("validation", {})
    analysis_cfg = config.get("analysis", {})
    chosen_strategy = strategy if strategy != "auto" else validation_cfg.get("strategy", "auto")
    _require_non_skip_strategy(str(chosen_strategy))
    chosen_owner = execution_owner or str(validation_cfg.get("execution_owner", "codex-host"))
    if chosen_owner not in {"codex-host", "oracle"}:
        raise RuntimeError(f"Unsupported execution_owner: {chosen_owner}")

    timeout_seconds = int(analysis_cfg.get("model_timeout_seconds", 300))
    executor = CLIModelExecutor(timeout_seconds=timeout_seconds)

    repo_root = Path(__file__).resolve().parents[2]
    prompt_path = Path(str(validation_cfg.get("trigger_prompt_template_path", "src/v2/prompts/codex_trigger_prompt.txt")))
    if not prompt_path.is_absolute():
        prompt_path = repo_root / prompt_path
    if not prompt_path.exists():
        raise RuntimeError(f"Trigger prompt template not found: {prompt_path}")
    prompt_template = prompt_path.read_text(encoding="utf-8")

    required_positive = int(validation_cfg.get("multishot_required_positive", verify_runs))
    required_positive = max(1, min(required_positive, max_shots))
    force_codex_pov_for_asan = bool(validation_cfg.get("multishot_force_codex_pov_for_asan", True))

    live_report_name = str(validation_cfg.get("live_report_name", "multishot_live_report.json"))
    live_report_path = run_paths["validate"] / live_report_name

    skill_references = [
        str((repo_root / "skills" / "findvuln-ingest" / "SKILL.md").resolve()),
        str((repo_root / "skills" / "findvuln-analyze" / "SKILL.md").resolve()),
        str((repo_root / "skills" / "findvuln-validate" / "SKILL.md").resolve()),
        str((repo_root / "skills" / "findvuln-multishot-validate" / "SKILL.md").resolve()),
    ]

    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "validate",
            "event": "start",
            "run_id": run_id,
            "verify_runs": verify_runs,
            "strategy": chosen_strategy,
            "mode": "multi-shot",
            "execution_owner": chosen_owner,
            "max_shots": max_shots,
            "required_positive": required_positive,
            "force_codex_pov_for_asan": force_codex_pov_for_asan,
        },
    )

    target_results: list[ValidateTargetResult] = []
    missing_runtime_evidence: list[str] = []

    for t in analyze.get("targets", []):
        target_id = str(t["target_id"])
        target_bundle = bundle_targets.get(target_id)
        if not target_bundle:
            continue

        profile = get_profile(str(t["language_profile"]["codeql_language"]))
        oracle = SandboxOracle(
            timeout=int(validation_cfg.get("timeout_seconds", 120)),
            asan_flags=str(config.get("sandbox", {}).get("asan_flags", "-fsanitize=address -fno-omit-frame-pointer -g")),
            compiler=str(config.get("sandbox", {}).get("compiler", "gcc")),
            verification_strategy=chosen_strategy,
        )

        finals: list[FinalFinding] = []
        for finding in t.get("findings", []):
            finding_id = str(finding.get("finding_id", ""))
            adjudication_history = [_to_adjudication_record(x) for x in finding.get("adjudication_history", [])]
            evidences: list[ValidationEvidence] = []
            attempts_summary: list[dict[str, Any]] = []

            consensus_vulnerable = finding.get("consensus_vulnerable")
            final_decision = str(finding.get("final_decision", "needs-human-review"))

            positives = 0
            codex_fail_streak = 0

            if final_decision == "consensus" and consensus_vulnerable is True:
                primary_file = str(finding.get("primary_file", ""))
                source_abs = None
                if primary_file:
                    source_abs = str((run_paths["snapshots"] / target_id / primary_file).resolve())

                for shot in range(1, max_shots + 1):
                    prompt = _build_trigger_prompt(
                        template=prompt_template,
                        finding=finding,
                        target_id=target_id,
                        language=profile.codeql_language,
                        snapshot_root=str(t.get("snapshot_root", "")),
                        shot_index=shot,
                        attempts=attempts_summary,
                        skill_references=skill_references,
                    )

                    raw = executor.run("codex", codex_cli, prompt)
                    if not raw.ok:
                        codex_fail_streak += 1
                        ev = ValidationEvidence(
                            run_index=shot,
                            verdict="codex_error",
                            exit_code=raw.returncode,
                            is_positive=False,
                            executed=False,
                            execution_owner=chosen_owner,
                            stderr_tail=(raw.error or raw.stderr)[-2000:],
                        )
                        evidences.append(ev)
                        attempts_summary.append(_attempt_stub(ev))
                    else:
                        try:
                            plan: TriggerPlan = parse_trigger_plan("codex", raw.stdout)
                            codex_fail_streak = 0
                        except Exception as exc:
                            codex_fail_streak += 1
                            ev = ValidationEvidence(
                                run_index=shot,
                                verdict="codex_parse_error",
                                exit_code=-1,
                                is_positive=False,
                                executed=False,
                                execution_owner=chosen_owner,
                                stderr_tail=str(exc)[-2000:],
                            )
                            evidences.append(ev)
                            attempts_summary.append(_attempt_stub(ev))
                        else:
                            if not plan.should_attempt:
                                ev = ValidationEvidence(
                                    run_index=shot,
                                    verdict="skipped",
                                    exit_code=0,
                                    is_positive=False,
                                    executed=False,
                                    execution_owner=chosen_owner,
                                    execution_target=plan.execution_target,
                                    prepare_commands=list(plan.prepare_commands),
                                    verify_command=plan.verify_command,
                                    expected_signal=plan.expected_signal,
                                    trigger_kind=plan.trigger_kind,
                                    trigger_command=plan.command,
                                    pov_preview=(plan.pov_stdin[:200] + ("..." if len(plan.pov_stdin) > 200 else "")),
                                    plan_confidence=plan.confidence,
                                    plan_rationale=plan.rationale,
                                )
                                evidences.append(ev)
                                attempts_summary.append(_attempt_stub(ev))
                                append_event(
                                    events_path,
                                    {
                                        "ts": datetime.now(timezone.utc).isoformat(),
                                        "stage": "validate",
                                        "event": "multishot_attempt",
                                        "target_id": target_id,
                                        "finding_id": finding_id,
                                        "shot": shot,
                                        "verdict": ev.verdict,
                                        "is_positive": ev.is_positive,
                                    },
                                )
                                break

                            if chosen_owner == "codex-host":
                                verify_command = str(plan.verify_command or "").strip()
                                expected_signal = str(plan.expected_signal or "").strip()
                                if plan.execution_target != "host_docker":
                                    ev = ValidationEvidence(
                                        run_index=shot,
                                        verdict="codex_parse_error",
                                        exit_code=-1,
                                        is_positive=False,
                                        executed=False,
                                        execution_owner=chosen_owner,
                                        execution_target=plan.execution_target,
                                        prepare_commands=list(plan.prepare_commands),
                                        verify_command=verify_command,
                                        expected_signal=expected_signal,
                                        stderr_tail="execution_target must be 'host_docker' for codex-host mode.",
                                        trigger_kind=plan.trigger_kind,
                                        trigger_command=plan.command,
                                        plan_confidence=plan.confidence,
                                        plan_rationale=plan.rationale,
                                    )
                                    evidences.append(ev)
                                    attempts_summary.append(_attempt_stub(ev))
                                elif not verify_command:
                                    ev = ValidationEvidence(
                                        run_index=shot,
                                        verdict="codex_parse_error",
                                        exit_code=-1,
                                        is_positive=False,
                                        executed=False,
                                        execution_owner=chosen_owner,
                                        execution_target=plan.execution_target,
                                        prepare_commands=list(plan.prepare_commands),
                                        verify_command=verify_command,
                                        expected_signal=expected_signal,
                                        stderr_tail="verify_command is required for codex-host mode.",
                                        trigger_kind=plan.trigger_kind,
                                        trigger_command=plan.command,
                                        plan_confidence=plan.confidence,
                                        plan_rationale=plan.rationale,
                                    )
                                    evidences.append(ev)
                                    attempts_summary.append(_attempt_stub(ev))
                                elif not expected_signal:
                                    ev = ValidationEvidence(
                                        run_index=shot,
                                        verdict="codex_parse_error",
                                        exit_code=-1,
                                        is_positive=False,
                                        executed=False,
                                        execution_owner=chosen_owner,
                                        execution_target=plan.execution_target,
                                        prepare_commands=list(plan.prepare_commands),
                                        verify_command=verify_command,
                                        expected_signal=expected_signal,
                                        stderr_tail="expected_signal is required for codex-host mode.",
                                        trigger_kind=plan.trigger_kind,
                                        trigger_command=plan.command,
                                        plan_confidence=plan.confidence,
                                        plan_rationale=plan.rationale,
                                    )
                                    evidences.append(ev)
                                    attempts_summary.append(_attempt_stub(ev))
                                else:
                                    timeout = int(validation_cfg.get("timeout_seconds", 120))
                                    project_cwd = str(t.get("snapshot_root", ""))
                                    prepare_error = ""
                                    prepare_out = ""
                                    prepare_err = ""
                                    prepare_exit = 0
                                    prepare_failed = False
                                    for prep_cmd in plan.prepare_commands:
                                        rc, out, err, err_kind = _run_host_command(prep_cmd, project_cwd, timeout)
                                        if err_kind == "timeout":
                                            prepare_failed = True
                                            prepare_error = "timeout"
                                            prepare_exit = -1
                                            prepare_out, prepare_err = out, err
                                            break
                                        if err_kind:
                                            prepare_failed = True
                                            prepare_error = "error"
                                            prepare_exit = -1
                                            prepare_out, prepare_err = out, err
                                            break
                                        if rc != 0:
                                            prepare_failed = True
                                            prepare_error = "nonzero"
                                            prepare_exit = rc
                                            prepare_out, prepare_err = out, err
                                            break

                                    if prepare_failed:
                                        verdict = "timeout" if prepare_error == "timeout" else "host_prepare_error"
                                        ev = ValidationEvidence(
                                            run_index=shot,
                                            verdict=verdict,
                                            exit_code=prepare_exit,
                                            is_positive=False,
                                            executed=True,
                                            execution_owner=chosen_owner,
                                            execution_target=plan.execution_target,
                                            prepare_commands=list(plan.prepare_commands),
                                            verify_command=verify_command,
                                            expected_signal=expected_signal,
                                            signal_matched=False,
                                            stdout_tail=prepare_out[-2000:] if prepare_out else "",
                                            stderr_tail=prepare_err[-2000:] if prepare_err else "",
                                            trigger_kind=plan.trigger_kind,
                                            trigger_command=plan.command,
                                            plan_confidence=plan.confidence,
                                            plan_rationale=plan.rationale,
                                        )
                                        evidences.append(ev)
                                        attempts_summary.append(_attempt_stub(ev))
                                    else:
                                        rc, out, err, err_kind = _run_host_command(verify_command, project_cwd, timeout)
                                        full_output = f"{out}\n{err}".strip()
                                        matched = _contains_signal(full_output, expected_signal)
                                        is_positive = matched
                                        if is_positive:
                                            positives += 1
                                        if err_kind == "timeout":
                                            verdict = "timeout"
                                        elif err_kind:
                                            verdict = "host_verify_error"
                                        else:
                                            verdict = "host_verify_match" if matched else "host_verify_no_match"
                                        ev = ValidationEvidence(
                                            run_index=shot,
                                            verdict=verdict,
                                            exit_code=rc,
                                            is_positive=is_positive,
                                            executed=True,
                                            execution_owner=chosen_owner,
                                            execution_target=plan.execution_target,
                                            prepare_commands=list(plan.prepare_commands),
                                            verify_command=verify_command,
                                            expected_signal=expected_signal,
                                            signal_matched=matched,
                                            stdout_tail=out[-2000:] if out else "",
                                            stderr_tail=err[-2000:] if err else "",
                                            trigger_kind=plan.trigger_kind,
                                            trigger_command=plan.command,
                                            plan_confidence=plan.confidence,
                                            plan_rationale=plan.rationale,
                                        )
                                        evidences.append(ev)
                                        attempts_summary.append(_attempt_stub(ev))
                            else:
                                pov_arg = target_bundle.get("pov_file")
                                custom_test_cmd: str | None = None
                                custom_run_cmd: str | None = None
                                pov_artifact_path = ""
                                pov_sha256 = ""

                                if plan.trigger_kind == "pov_stdin" and plan.pov_stdin:
                                    pov_artifact_path, pov_sha256 = _persist_pov_artifact(
                                        validate_dir=run_paths["validate"],
                                        target_id=target_id,
                                        finding_id=finding_id,
                                        shot=shot,
                                        pov_text=plan.pov_stdin,
                                    )
                                    pov_arg = pov_artifact_path
                                elif plan.trigger_kind == "command" and plan.command.strip():
                                    if profile.sandbox_strategy == "asan":
                                        custom_run_cmd = plan.command.strip()
                                    else:
                                        custom_test_cmd = plan.command.strip()

                                if profile.sandbox_strategy == "asan" and force_codex_pov_for_asan:
                                    has_codex_pov_control = bool(
                                        (plan.trigger_kind == "pov_stdin" and plan.pov_stdin)
                                        or (plan.trigger_kind == "command" and plan.command.strip())
                                    )
                                    if not has_codex_pov_control:
                                        ev = ValidationEvidence(
                                            run_index=shot,
                                            verdict="codex_no_pov_plan",
                                            exit_code=-1,
                                            is_positive=False,
                                            executed=False,
                                            execution_owner="oracle",
                                            execution_target="oracle_sandbox",
                                            trigger_kind=plan.trigger_kind,
                                            trigger_command=plan.command,
                                            pov_preview=(plan.pov_stdin[:200] + ("..." if len(plan.pov_stdin) > 200 else "")),
                                            plan_confidence=plan.confidence,
                                            plan_rationale=plan.rationale,
                                        )
                                        evidences.append(ev)
                                        attempts_summary.append(_attempt_stub(ev))
                                        append_event(
                                            events_path,
                                            {
                                                "ts": datetime.now(timezone.utc).isoformat(),
                                                "stage": "validate",
                                                "event": "multishot_attempt",
                                                "target_id": target_id,
                                                "finding_id": finding_id,
                                                "shot": shot,
                                                "verdict": ev.verdict,
                                                "is_positive": ev.is_positive,
                                                "positives": positives,
                                                "required_positive": required_positive,
                                            },
                                        )
                                        if codex_fail_streak >= 2:
                                            break
                                        continue

                                if profile.sandbox_strategy == "asan" and not source_abs:
                                    oracle_result = _oracle_unknown(
                                        "ASAN validation requires source_file but no location was provided."
                                    )
                                else:
                                    oracle_result = oracle.run(
                                        source_file=source_abs if profile.sandbox_strategy == "asan" else None,
                                        pov_file=pov_arg,
                                        patch_file=None,
                                        language_profile=profile,
                                        project_root=t.get("snapshot_root"),
                                        custom_test_command=custom_test_cmd,
                                        custom_run_command=custom_run_cmd,
                                    )

                                is_positive = _is_positive_evidence(oracle_result, profile.sandbox_strategy)
                                if is_positive:
                                    positives += 1

                                ev = ValidationEvidence(
                                    run_index=shot,
                                    verdict=oracle_result.verdict.value,
                                    exit_code=int(oracle_result.exit_code),
                                    is_positive=is_positive,
                                    executed=True,
                                    execution_owner="oracle",
                                    execution_target="oracle_sandbox",
                                    stdout_tail=oracle_result.stdout[-2000:] if oracle_result.stdout else "",
                                    stderr_tail=oracle_result.stderr[-2000:] if oracle_result.stderr else "",
                                    asan_report=oracle_result.asan_report,
                                    trigger_kind=plan.trigger_kind,
                                    trigger_command=plan.command,
                                    pov_preview=(plan.pov_stdin[:200] + ("..." if len(plan.pov_stdin) > 200 else "")),
                                    pov_artifact=pov_artifact_path,
                                    pov_sha256=pov_sha256,
                                    plan_confidence=plan.confidence,
                                    plan_rationale=plan.rationale,
                                )
                                evidences.append(ev)
                                attempts_summary.append(_attempt_stub(ev))

                    last = evidences[-1]
                    append_event(
                        events_path,
                        {
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "stage": "validate",
                            "event": "multishot_attempt",
                            "target_id": target_id,
                            "finding_id": finding_id,
                            "shot": shot,
                            "verdict": last.verdict,
                            "is_positive": last.is_positive,
                            "positives": positives,
                            "required_positive": required_positive,
                            "pov_artifact": last.pov_artifact,
                            "pov_sha256": last.pov_sha256,
                        },
                    )

                    write_json(
                        live_report_path,
                        {
                            "run_id": run_id,
                            "target_id": target_id,
                            "finding_id": finding_id,
                            "shot": shot,
                            "required_positive": required_positive,
                            "positives": positives,
                            "last_attempt": last.to_dict(),
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        },
                    )

                    if codex_fail_streak >= 2:
                        break
                    if positives >= required_positive:
                        break
                    remaining = max_shots - shot
                    if positives + remaining < required_positive:
                        break

            if final_decision == "consensus" and consensus_vulnerable is True:
                if not _has_runtime_evidence(evidences):
                    missing_runtime_evidence.append(finding_id)
                    append_event(
                        events_path,
                        {
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "stage": "validate",
                            "event": "runtime_evidence_missing",
                            "target_id": target_id,
                            "finding_id": finding_id,
                            "mode": "multi-shot",
                            "execution_owner": chosen_owner,
                        },
                    )

            status = _resolve_multishot_status(
                consensus_vulnerable=consensus_vulnerable,
                evidences=evidences,
                required_positive=required_positive,
            )

            evidence_score = 0.0
            if evidences:
                evidence_score = sum(1 for e in evidences if e.is_positive) / float(len(evidences))

            final = FinalFinding(
                finding_id=finding_id,
                rule_id=str(finding.get("rule_id", "unknown")),
                severity=str(finding.get("severity", "error")),
                message=str(finding.get("message", "")),
                primary_file=str(finding.get("primary_file", "")),
                primary_line=int(finding.get("primary_line", 0)),
                final_status=status,
                evidence_score=evidence_score,
                consensus_vulnerable=consensus_vulnerable,
                adjudication_history=adjudication_history,
                validation_evidence=evidences,
                stop_reason=str(finding.get("stop_reason", "")),
            )
            finals.append(final)

            append_event(
                events_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "stage": "validate",
                    "event": "finding_validated",
                    "target_id": target_id,
                    "finding_id": final.finding_id,
                    "status": final.final_status.value,
                    "evidence_score": final.evidence_score,
                    "mode": "multi-shot",
                },
            )

        target_results.append(
            ValidateTargetResult(
                target_id=target_id,
                snapshot_root=str(t.get("snapshot_root", "")),
                final_findings=finals,
                model_contribution=t.get("model_contribution", {}),
            )
        )

    result = ValidationResult(
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        verify_runs=verify_runs,
        strategy=chosen_strategy,
        targets=target_results,
    )

    reporting_cfg = config.get("reporting", {})
    json_path, html_path = write_validation_reports(
        result=result,
        output_dir=run_paths["validate"],
        json_name=str(reporting_cfg.get("json_name", "final_report.json")),
        html_name=str(reporting_cfg.get("html_name", "final_report.html")),
    )

    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "validate",
            "event": "complete",
            "json_report": str(json_path),
            "html_report": str(html_path),
            "mode": "multi-shot",
        },
    )

    if missing_runtime_evidence:
        raise RuntimeError(
            "Runtime evidence missing for consensus-vulnerable findings: "
            + ", ".join(missing_runtime_evidence[:20])
        )

    return str(json_path), str(html_path)
