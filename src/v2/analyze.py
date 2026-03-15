from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.codeql.wrapper import CodeQLRunner, filter_source_sink_chains
from src.v2.adjudicator import AdjudicationPolicy, adjudicate_round
from src.v2.contracts import (
    AdjudicationDecision,
    AdjudicationRecord,
    AnalyzeResult,
    AnalyzeTargetResult,
    FindingAnalysis,
    ScanTarget,
)
from src.v2.llm_cli import CLIModelExecutor, ParallelRoundRunner, parse_model_verdict
from src.v2.storage import append_event, ensure_run_layout, read_json, write_json

logger = logging.getLogger(__name__)
_DEFAULT_PROMPT_PATH = Path(__file__).parent / "prompts" / "codex_default_prompt.txt"


def _dict_to_scan_target(raw: dict[str, Any]) -> ScanTarget:
    return ScanTarget(
        target_id=str(raw["target_id"]),
        name=str(raw.get("name", raw["target_id"])),
        snapshot_root=str(raw["snapshot_root"]),
        original_source=str(raw.get("original_source", "")),
        commit=str(raw["commit"]) if raw.get("commit") else None,
        language=str(raw.get("language", "auto")),
        scan_mode=str(raw.get("scan_mode", "pack")),
        codeql_db_path=str(raw["codeql_db_path"]),
        pov_file=str(raw["pov_file"]) if raw.get("pov_file") else None,
        file_index=[str(x) for x in raw.get("file_index", [])],
    )


def _build_prompt(
    target: ScanTarget,
    finding: dict[str, Any],
    round_index: int,
    history: list[dict[str, Any]],
    prompt_template: str,
    skill_references: list[str],
) -> str:
    schema = {
        "is_vulnerable": "boolean",
        "summary": "string",
        "evidence_locations": [
            {
                "file": "string",
                "line": "integer",
                "reason": "string"
            }
        ],
        "cwe_id": "string|null",
        "cvss_estimate": "number|null",
        "reproduction_hypothesis": "string",
        "confidence": "number(0.0~1.0)",
    }

    history_json = json.dumps(history if history else [], indent=2)
    skill_ref_block = "\n".join(f"- {path}" for path in skill_references)
    rendered = prompt_template
    rendered = rendered.replace("{{SKILL_REFERENCES}}", skill_ref_block)
    rendered = rendered.replace("{{SCHEMA_JSON}}", json.dumps(schema, indent=2))
    rendered = rendered.replace("{{ROUND_INDEX}}", str(round_index))
    rendered = rendered.replace("{{TARGET_NAME}}", target.name)
    rendered = rendered.replace("{{SNAPSHOT_ROOT}}", target.snapshot_root)
    rendered = rendered.replace("{{CODEQL_FINDING_JSON}}", json.dumps(finding, indent=2))
    rendered = rendered.replace("{{ADJUDICATION_HISTORY_JSON}}", history_json)
    return rendered


def _build_history_stub(history: list[Any]) -> list[dict[str, Any]]:
    stubs: list[dict[str, Any]] = []
    for rec in history:
        stubs.append({
            "round": rec.round_index,
            "decision": rec.decision.value,
            "reason": rec.reason,
            "consensus_vulnerable": rec.consensus_vulnerable,
            "consensus_confidence": rec.consensus_confidence,
            "codex_summary": rec.codex.summary if rec.codex else None,
            "claude_summary": rec.claude.summary if rec.claude else None,
        })
    return stubs


def run_adjudicated_rounds(
    *,
    finding_id: str,
    finding: dict[str, Any],
    target: ScanTarget,
    max_rounds: int,
    codex_cli: str,
    claude_cli: str,
    runner: ParallelRoundRunner,
    policy: AdjudicationPolicy,
    max_consecutive_failures: int,
    model_contribution: dict[str, dict[str, int]],
    prompt_template: str,
    skill_references: list[str],
) -> FindingAnalysis:
    chain = finding.get("chain", [])
    primary = chain[0] if chain else {}
    analysis = FindingAnalysis(
        finding_id=finding_id,
        rule_id=str(finding.get("rule_id", "unknown")),
        severity=str(finding.get("severity", "error")),
        message=str(finding.get("message", "")),
        primary_file=str(primary.get("file", "")),
        primary_line=int(primary.get("line", 0) or 0),
        codeql_finding=finding,
        consecutive_failures={"codex": 0, "claude": 0},
    )

    for round_index in range(1, max_rounds + 1):
        prompt = _build_prompt(
            target=target,
            finding=finding,
            round_index=round_index,
            history=_build_history_stub(analysis.adjudication_history),
            prompt_template=prompt_template,
            skill_references=skill_references,
        )

        raw = runner.run_round(prompt, codex_cli, claude_cli)

        codex_verdict = None
        claude_verdict = None

        codex_res = raw["codex"]
        if codex_res.ok:
            try:
                codex_verdict = parse_model_verdict("codex", codex_res.stdout)
                analysis.consecutive_failures["codex"] = 0
                model_contribution["codex"]["valid_rounds"] += 1
            except Exception:
                analysis.consecutive_failures["codex"] += 1
        else:
            analysis.consecutive_failures["codex"] += 1

        claude_res = raw["claude"]
        if claude_res.ok:
            try:
                claude_verdict = parse_model_verdict("claude", claude_res.stdout)
                analysis.consecutive_failures["claude"] = 0
                model_contribution["claude"]["valid_rounds"] += 1
            except Exception:
                analysis.consecutive_failures["claude"] += 1
        else:
            analysis.consecutive_failures["claude"] += 1

        if analysis.consecutive_failures["codex"] >= max_consecutive_failures:
            analysis.final_decision = "needs-human-review"
            analysis.stop_reason = "codex failed consecutively"
            return analysis

        if analysis.consecutive_failures["claude"] >= max_consecutive_failures:
            analysis.final_decision = "needs-human-review"
            analysis.stop_reason = "claude failed consecutively"
            return analysis

        record = adjudicate_round(
            round_index=round_index,
            codex=codex_verdict,
            claude=claude_verdict,
            policy=policy,
        )
        analysis.adjudication_history.append(record)

        if record.decision.value == "consensus" and record.evidence_sufficient:
            analysis.final_decision = "consensus"
            analysis.consensus_vulnerable = record.consensus_vulnerable
            analysis.confidence = record.consensus_confidence
            analysis.stop_reason = "consensus+evidence"
            if codex_verdict is not None:
                model_contribution["codex"]["consensus_supports"] += 1
            if claude_verdict is not None:
                model_contribution["claude"]["consensus_supports"] += 1
            return analysis

    analysis.final_decision = "needs-human-review"
    analysis.stop_reason = "max rounds reached"
    return analysis


def run_codex_single_pass(
    *,
    finding_id: str,
    finding: dict[str, Any],
    target: ScanTarget,
    codex_cli: str,
    executor: CLIModelExecutor,
    policy: AdjudicationPolicy,
    model_contribution: dict[str, dict[str, int]],
    prompt_template: str,
    skill_references: list[str],
) -> FindingAnalysis:
    chain = finding.get("chain", [])
    primary = chain[0] if chain else {}
    analysis = FindingAnalysis(
        finding_id=finding_id,
        rule_id=str(finding.get("rule_id", "unknown")),
        severity=str(finding.get("severity", "error")),
        message=str(finding.get("message", "")),
        primary_file=str(primary.get("file", "")),
        primary_line=int(primary.get("line", 0) or 0),
        codeql_finding=finding,
        consecutive_failures={"codex": 0, "claude": 0},
    )

    prompt = _build_prompt(
        target=target,
        finding=finding,
        round_index=1,
        history=[],
        prompt_template=prompt_template,
        skill_references=skill_references,
    )

    raw = executor.run("codex", codex_cli, prompt)
    if not raw.ok:
        analysis.final_decision = "needs-human-review"
        analysis.stop_reason = "codex single pass execution failed"
        analysis.consecutive_failures["codex"] = 1
        return analysis

    try:
        codex_verdict = parse_model_verdict("codex", raw.stdout)
    except Exception:
        analysis.final_decision = "needs-human-review"
        analysis.stop_reason = "codex single pass output parse failed"
        analysis.consecutive_failures["codex"] = 1
        return analysis

    model_contribution["codex"]["valid_rounds"] += 1

    evidence_sufficient = bool(codex_verdict.evidence_locations) if policy.require_evidence else True
    confidence_ok = codex_verdict.confidence >= policy.min_consensus_confidence
    accepted = evidence_sufficient and confidence_ok

    decision = AdjudicationDecision.CONSENSUS if accepted else AdjudicationDecision.DISPUTE
    reason = (
        "single-pass accepted with sufficient confidence and evidence"
        if accepted
        else "single-pass insufficient confidence or evidence"
    )
    record = AdjudicationRecord(
        round_index=1,
        decision=decision,
        reason=reason,
        evidence_sufficient=evidence_sufficient,
        consensus_vulnerable=codex_verdict.is_vulnerable if accepted else None,
        consensus_confidence=codex_verdict.confidence,
        codex=codex_verdict,
        claude=None,
    )
    analysis.adjudication_history.append(record)

    if accepted:
        analysis.final_decision = "consensus"
        analysis.consensus_vulnerable = codex_verdict.is_vulnerable
        analysis.confidence = codex_verdict.confidence
        analysis.stop_reason = "single-pass accepted"
        model_contribution["codex"]["consensus_supports"] += 1
    else:
        analysis.final_decision = "needs-human-review"
        analysis.stop_reason = "single-pass insufficient confidence/evidence"

    return analysis


def run_analyze(
    *,
    run_id: str,
    runs_root: str,
    config: dict[str, Any],
    topology: str,
    max_rounds: int,
    codex_cli: str,
    claude_cli: str,
) -> Path:
    run_paths = ensure_run_layout(run_id, runs_root)
    events_path = run_paths["logs"] / "events.jsonl"

    bundle_path = run_paths["ingest"] / "scan_bundle.json"
    if not bundle_path.exists():
        raise RuntimeError(f"Scan bundle not found: {bundle_path}")

    bundle = read_json(bundle_path)
    targets = [_dict_to_scan_target(x) for x in bundle.get("targets", [])]
    if not targets:
        raise RuntimeError("No targets found in scan bundle")

    append_event(events_path, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": "analyze",
        "event": "start",
        "run_id": run_id,
        "targets": len(targets),
        "topology": topology,
    })

    codeql_cfg = config.get("codeql", {})
    analysis_cfg = config.get("analysis", {})
    repo_root = Path(__file__).resolve().parents[2]
    prompt_path = Path(str(analysis_cfg.get("prompt_template_path", _DEFAULT_PROMPT_PATH)))
    if not prompt_path.is_absolute():
        prompt_path = repo_root / prompt_path
    if prompt_path.exists():
        prompt_template = prompt_path.read_text(encoding="utf-8")
    else:
        prompt_template = _DEFAULT_PROMPT_PATH.read_text(encoding="utf-8")

    skill_references = [
        str((repo_root / "skills" / "findvuln-ingest" / "SKILL.md").resolve()),
        str((repo_root / "skills" / "findvuln-analyze" / "SKILL.md").resolve()),
        str((repo_root / "skills" / "findvuln-validate" / "SKILL.md").resolve()),
    ]

    timeout_seconds = int(analysis_cfg.get("model_timeout_seconds", 300))
    runner = ParallelRoundRunner(executor=CLIModelExecutor(timeout_seconds=timeout_seconds))
    policy = AdjudicationPolicy(
        min_consensus_confidence=float(analysis_cfg.get("min_consensus_confidence", 0.60)),
        require_evidence=bool(analysis_cfg.get("require_evidence", True)),
    )

    # Keep v1 detect-only policy: no patch generation/apply.
    target_results: list[AnalyzeTargetResult] = []
    for target in targets:
        codeql = CodeQLRunner(
            cli_path=codeql_cfg.get("cli_path", "codeql"),
            language=target.language,
            query_dir=codeql_cfg.get("custom_query_dir", "src/codeql/queries"),
            threads=int(codeql_cfg.get("threads", 4)),
            timeout=int(codeql_cfg.get("timeout_seconds", 7200)),
            query_mode=target.scan_mode,
            build_command=codeql_cfg.get("build_command"),
        )

        findings, profile = codeql.analyze(target.snapshot_root, target.codeql_db_path)
        findings = filter_source_sink_chains(findings)

        contribution = {
            "codex": {"valid_rounds": 0, "consensus_supports": 0},
            "claude": {"valid_rounds": 0, "consensus_supports": 0},
        }

        analyses: list[FindingAnalysis] = []
        for idx, finding in enumerate(findings, 1):
            finding_id = f"{target.target_id}-finding-{idx:04d}"
            if topology == "parallel-adjudicated":
                fa = run_adjudicated_rounds(
                    finding_id=finding_id,
                    finding=finding,
                    target=target,
                    max_rounds=max_rounds,
                    codex_cli=codex_cli,
                    claude_cli=claude_cli,
                    runner=runner,
                    policy=policy,
                    max_consecutive_failures=int(analysis_cfg.get("max_consecutive_failures", 2)),
                    model_contribution=contribution,
                    prompt_template=prompt_template,
                    skill_references=skill_references,
                )
            elif topology == "codex-single-pass":
                fa = run_codex_single_pass(
                    finding_id=finding_id,
                    finding=finding,
                    target=target,
                    codex_cli=codex_cli,
                    executor=runner.executor,
                    policy=policy,
                    model_contribution=contribution,
                    prompt_template=prompt_template,
                    skill_references=skill_references,
                )
            else:
                raise RuntimeError(f"Unsupported topology: {topology}")
            analyses.append(fa)

            append_event(events_path, {
                "ts": datetime.now(timezone.utc).isoformat(),
                "stage": "analyze",
                "event": "finding_analyzed",
                "target_id": target.target_id,
                "finding_id": fa.finding_id,
                "decision": fa.final_decision,
                "stop_reason": fa.stop_reason,
                "confidence": fa.confidence,
            })

        target_results.append(
            AnalyzeTargetResult(
                target_id=target.target_id,
                snapshot_root=target.snapshot_root,
                language_profile=asdict(profile),
                findings_total=len(findings),
                findings_selected=len(analyses),
                findings=analyses,
                model_contribution=contribution,
            )
        )

    result = AnalyzeResult(
        run_id=run_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        topology=topology,
        max_rounds=max_rounds,
        targets=target_results,
    )

    out = run_paths["analyze"] / "analyze_result.json"
    write_json(out, result.to_dict())

    append_event(events_path, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": "analyze",
        "event": "complete",
        "result": str(out),
    })

    return out
