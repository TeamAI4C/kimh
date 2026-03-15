from __future__ import annotations

import fnmatch
import json
import logging
import re
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.codeql.wrapper import CodeQLRunner, filter_source_sink_chains
from src.lang_detect import LanguageProfile, detect_or_resolve
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
_DEFAULT_CODEX_QL_PROMPT_PATH = Path(__file__).parent / "prompts" / "codex_ql_query_prompt.txt"
_DEFAULT_EXCLUDE_PRIMARY_PATH_GLOBS = [
    "test/**",
    "tests/**",
    "**/test/**",
    "**/tests/**",
    "**/testing/**",
    "**/*_test.py",
    "**/test_*.py",
]


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
        exclude_paths=[str(x) for x in raw.get("exclude_paths", []) if str(x).strip()],
    )


def _normalize_path(path: str) -> str:
    p = str(path or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _find_exclude_pattern(path: str, patterns: list[str]) -> str | None:
    norm = _normalize_path(path)
    if not norm or not patterns:
        return None
    for raw_pattern in patterns:
        pattern = _normalize_path(raw_pattern)
        if not pattern:
            continue
        if fnmatch.fnmatch(norm, pattern):
            return raw_pattern
    return None


def _filter_findings_by_primary_path(
    findings: list[dict[str, Any]],
    patterns: list[str],
) -> tuple[list[dict[str, Any]], list[tuple[dict[str, Any], str]]]:
    if not patterns:
        return findings, []

    kept: list[dict[str, Any]] = []
    excluded: list[tuple[dict[str, Any], str]] = []
    for finding in findings:
        chain = finding.get("chain", [])
        primary = chain[0] if chain else {}
        primary_file = str(primary.get("file", ""))
        matched = _find_exclude_pattern(primary_file, patterns)
        if matched:
            excluded.append((finding, matched))
            continue
        kept.append(finding)
    return kept, excluded


def _safe_name(name: str) -> str:
    out = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(name).strip())
    out = out.strip("-._")
    return out or "query"


def _normalize_timeout_seconds(value: Any, default: int) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    return parsed if parsed > 0 else None


def _timeout_for_log(timeout_seconds: int | None) -> int | None:
    return int(timeout_seconds) if timeout_seconds is not None else None


def _extract_first_json_object(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue

            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    raw = text[start : i + 1]
                    try:
                        obj = json.loads(raw)
                    except json.JSONDecodeError:
                        break
                    if isinstance(obj, dict):
                        return obj
                    break
        start = text.find("{", start + 1)
    return None


def _parse_generated_queries(output: str, max_queries: int) -> list[dict[str, str]]:
    obj = _extract_first_json_object(output)
    if obj is None:
        raise ValueError("No JSON object found in Codex QL output")

    queries_raw = obj.get("queries")
    if not isinstance(queries_raw, list):
        raise ValueError("Missing 'queries' array in Codex QL output")

    parsed: list[dict[str, str]] = []
    for idx, item in enumerate(queries_raw, 1):
        if not isinstance(item, dict):
            continue
        ql_code = str(item.get("ql_code", "")).strip()
        if not ql_code:
            continue
        name = str(item.get("name", "")).strip() or f"generated-query-{idx}"
        purpose = str(item.get("purpose", "")).strip()
        parsed.append(
            {
                "name": name,
                "purpose": purpose,
                "ql_code": ql_code,
            }
        )
        if len(parsed) >= max_queries:
            break

    if not parsed:
        raise ValueError("Codex QL output did not include any usable query")
    return parsed


def _dedup_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for d in findings:
        chain = d.get("chain", [])
        if chain:
            key = f"{d.get('rule_id','unknown')}:{chain[0].get('file','')}:{chain[0].get('line',0)}"
        else:
            key = f"{d.get('rule_id','unknown')}:{d.get('message','')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def _write_generated_qlpack(target_dir: Path, target_id: str, profile: LanguageProfile) -> None:
    pack_ref = str(profile.query_pack).split(":", 1)[0].strip() or "codeql/ql"
    pack_name = f"findvuln/generated/{_safe_name(target_id)}"
    qlpack = (
        f"name: {pack_name}\n"
        "version: 0.0.0\n"
        "dependencies:\n"
        f"  {pack_ref}: \"*\"\n"
    )
    (target_dir / "qlpack.yml").write_text(qlpack, encoding="utf-8")


def _build_codex_ql_prompt(
    *,
    template: str,
    target: ScanTarget,
    language: str,
    max_queries: int,
    file_index: list[str],
    recent_findings: list[dict[str, Any]],
    skill_references: list[str],
) -> str:
    schema = {
        "queries": [
            {
                "name": "string",
                "purpose": "string",
                "ql_code": "string",
            }
        ]
    }
    rendered = template
    rendered = rendered.replace("{{SKILL_REFERENCES}}", "\n".join(f"- {x}" for x in skill_references))
    rendered = rendered.replace("{{SCHEMA_JSON}}", json.dumps(schema, indent=2))
    rendered = rendered.replace("{{TARGET_JSON}}", json.dumps(target.to_dict(), indent=2))
    rendered = rendered.replace("{{LANGUAGE}}", language)
    rendered = rendered.replace("{{MAX_QUERIES}}", str(max_queries))
    rendered = rendered.replace("{{FILE_INDEX_JSON}}", json.dumps(file_index, indent=2))
    rendered = rendered.replace("{{RECENT_FINDINGS_JSON}}", json.dumps(recent_findings, indent=2))
    return rendered


def _build_compile_retry_prompt(
    *,
    query_name: str,
    purpose: str,
    ql_code: str,
    compile_error: str,
    retry_index: int,
    max_retries: int,
) -> str:
    schema = {
        "queries": [
            {
                "name": "string",
                "purpose": "string",
                "ql_code": "string",
            }
        ]
    }
    return (
        "You are fixing a CodeQL query that failed to compile.\n"
        f"Retry {retry_index}/{max_retries}.\n"
        "Return ONLY one JSON object with this schema:\n"
        f"{json.dumps(schema, indent=2)}\n"
        "Provide exactly one query in queries[] with corrected ql_code.\n\n"
        f"Previous name: {query_name}\n"
        f"Previous purpose: {purpose}\n"
        "Previous query:\n"
        f"{ql_code}\n\n"
        "Compile error:\n"
        f"{compile_error}\n"
    )


def _load_recent_findings_context(analyze_path: Path, target_id: str) -> list[dict[str, Any]]:
    if not analyze_path.exists():
        return []
    try:
        prior = read_json(analyze_path)
    except Exception:
        return []
    for t in prior.get("targets", []):
        if str(t.get("target_id", "")) != target_id:
            continue
        ctx: list[dict[str, Any]] = []
        for finding in t.get("findings", []):
            ctx.append(
                {
                    "finding_id": str(finding.get("finding_id", "")),
                    "rule_id": str(finding.get("rule_id", "")),
                    "message": str(finding.get("message", "")),
                    "primary_file": str(finding.get("primary_file", "")),
                    "primary_line": int(finding.get("primary_line", 0) or 0),
                    "final_decision": str(finding.get("final_decision", "")),
                }
            )
            if len(ctx) >= 20:
                break
        return ctx
    return []


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


def _generate_and_compile_codex_queries(
    *,
    run_paths: dict[str, Path],
    events_path: Path,
    target: ScanTarget,
    profile: LanguageProfile,
    codex_cli: str,
    executor: CLIModelExecutor,
    prompt_template: str,
    max_queries: int,
    max_retries: int,
    exclude_patterns: list[str],
    recent_findings: list[dict[str, Any]],
    skill_references: list[str],
    codeql: CodeQLRunner,
) -> dict[str, Any]:
    target_dir = run_paths["codeql_generated"] / target.target_id
    target_dir.mkdir(parents=True, exist_ok=True)
    generation_plan_path = target_dir / "generation_plan.json"
    compile_results_path = target_dir / "compile_results.json"

    filtered_index = [
        f
        for f in target.file_index
        if not _find_exclude_pattern(str(f), exclude_patterns)
    ][:400]

    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "codex_ql",
            "event": "start",
            "target_id": target.target_id,
            "max_queries": max_queries,
            "max_retries": max_retries,
            "file_index_size": len(filtered_index),
            "timeout_seconds": _timeout_for_log(executor.timeout_seconds),
        },
    )

    prompt = _build_codex_ql_prompt(
        template=prompt_template,
        target=target,
        language=profile.codeql_language,
        max_queries=max_queries,
        file_index=filtered_index,
        recent_findings=recent_findings,
        skill_references=skill_references,
    )

    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "codex_ql",
            "event": "model_request_start",
            "target_id": target.target_id,
            "request_kind": "initial_generation",
            "timeout_seconds": _timeout_for_log(executor.timeout_seconds),
        },
    )
    started = time.monotonic()
    raw = executor.run("codex", codex_cli, prompt)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "codex_ql",
            "event": "model_request_complete",
            "target_id": target.target_id,
            "request_kind": "initial_generation",
            "ok": bool(raw.ok),
            "returncode": int(raw.returncode),
            "elapsed_ms": elapsed_ms,
            "stdout_bytes": len(raw.stdout.encode("utf-8")) if raw.stdout else 0,
            "stderr_bytes": len(raw.stderr.encode("utf-8")) if raw.stderr else 0,
            "error": (raw.error or "")[-500:],
        },
    )
    if not raw.ok:
        write_json(
            generation_plan_path,
            {
                "target_id": target.target_id,
                "ok": False,
                "error": raw.error or raw.stderr,
                "raw_output": raw.stdout,
                "queries": [],
            },
        )
        write_json(
            compile_results_path,
            {
                "target_id": target.target_id,
                "compiled_queries": [],
            },
        )
        append_event(
            events_path,
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "stage": "codex_ql",
                "event": "complete",
                "target_id": target.target_id,
                "generated_queries_total": 0,
                "generated_queries_compiled": 0,
                "generated_queries_failed": 0,
                "error": (raw.error or raw.stderr)[-500:],
            },
        )
        return {
            "compiled_query_paths": [],
            "generated_queries_total": 0,
            "generated_queries_compiled": 0,
            "generated_queries_failed": 0,
            "generated_query_dir": str(target_dir),
        }

    try:
        queries = _parse_generated_queries(raw.stdout, max_queries=max_queries)
    except Exception as exc:
        write_json(
            generation_plan_path,
            {
                "target_id": target.target_id,
                "ok": False,
                "error": str(exc),
                "raw_output": raw.stdout,
                "queries": [],
            },
        )
        write_json(
            compile_results_path,
            {
                "target_id": target.target_id,
                "compiled_queries": [],
            },
        )
        append_event(
            events_path,
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "stage": "codex_ql",
                "event": "complete",
                "target_id": target.target_id,
                "generated_queries_total": 0,
                "generated_queries_compiled": 0,
                "generated_queries_failed": 0,
                "error": str(exc),
            },
        )
        return {
            "compiled_query_paths": [],
            "generated_queries_total": 0,
            "generated_queries_compiled": 0,
            "generated_queries_failed": 0,
            "generated_query_dir": str(target_dir),
        }
    write_json(
        generation_plan_path,
        {
            "target_id": target.target_id,
            "ok": True,
            "raw_output": raw.stdout,
            "queries": queries,
        },
    )

    _write_generated_qlpack(target_dir, target.target_id, profile)

    compiled_paths: list[str] = []
    compile_records: list[dict[str, Any]] = []
    failed_count = 0
    for idx, q in enumerate(queries, 1):
        name = q["name"]
        purpose = q["purpose"]
        ql_code = q["ql_code"]
        query_filename = f"query-{idx:02d}-{_safe_name(name)}.ql"
        query_path = target_dir / query_filename
        query_path.write_text(ql_code.rstrip() + "\n", encoding="utf-8")

        append_event(
            events_path,
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "stage": "codex_ql",
                "event": "query_generated",
                "target_id": target.target_id,
                "query_name": name,
                "query_path": str(query_path),
            },
        )

        attempts: list[dict[str, Any]] = []
        compiled = False
        current_code = ql_code
        for attempt in range(0, max_retries + 1):
            ok, output = codeql.compile_query(query_path, cwd=target_dir)
            attempts.append(
                {
                    "attempt": attempt,
                    "ok": ok,
                    "output": output[-4000:] if output else "",
                }
            )
            if ok:
                compiled = True
                compiled_paths.append(str(query_path))
                append_event(
                    events_path,
                    {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "stage": "codex_ql",
                        "event": "compile_passed",
                        "target_id": target.target_id,
                        "query_name": name,
                        "query_path": str(query_path),
                        "attempt": attempt,
                    },
                )
                break

            append_event(
                events_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "stage": "codex_ql",
                    "event": "compile_failed",
                    "target_id": target.target_id,
                    "query_name": name,
                    "query_path": str(query_path),
                    "attempt": attempt,
                    "error": output[-500:] if output else "",
                },
            )

            if attempt >= max_retries:
                break

            retry_prompt = _build_compile_retry_prompt(
                query_name=name,
                purpose=purpose,
                ql_code=current_code,
                compile_error=output,
                retry_index=attempt + 1,
                max_retries=max_retries,
            )
            append_event(
                events_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "stage": "codex_ql",
                    "event": "model_request_start",
                    "target_id": target.target_id,
                    "request_kind": "compile_retry",
                    "query_name": name,
                    "attempt": attempt + 1,
                    "timeout_seconds": _timeout_for_log(executor.timeout_seconds),
                },
            )
            retry_started = time.monotonic()
            retry_raw = executor.run("codex", codex_cli, retry_prompt)
            retry_elapsed_ms = int((time.monotonic() - retry_started) * 1000)
            append_event(
                events_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "stage": "codex_ql",
                    "event": "model_request_complete",
                    "target_id": target.target_id,
                    "request_kind": "compile_retry",
                    "query_name": name,
                    "attempt": attempt + 1,
                    "ok": bool(retry_raw.ok),
                    "returncode": int(retry_raw.returncode),
                    "elapsed_ms": retry_elapsed_ms,
                    "stdout_bytes": len(retry_raw.stdout.encode("utf-8")) if retry_raw.stdout else 0,
                    "stderr_bytes": len(retry_raw.stderr.encode("utf-8")) if retry_raw.stderr else 0,
                    "error": (retry_raw.error or "")[-500:],
                },
            )
            if not retry_raw.ok:
                attempts.append(
                    {
                        "attempt": attempt + 1,
                        "ok": False,
                        "output": (retry_raw.error or retry_raw.stderr)[-2000:],
                        "stage": "retry_generation_failed",
                    }
                )
                continue

            try:
                retry_queries = _parse_generated_queries(retry_raw.stdout, max_queries=1)
            except Exception as exc:
                attempts.append(
                    {
                        "attempt": attempt + 1,
                        "ok": False,
                        "output": str(exc),
                        "stage": "retry_parse_failed",
                    }
                )
                continue

            repaired = retry_queries[0]
            current_code = repaired["ql_code"]
            name = repaired["name"] or name
            purpose = repaired["purpose"] or purpose
            query_path.write_text(current_code.rstrip() + "\n", encoding="utf-8")
            append_event(
                events_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "stage": "codex_ql",
                    "event": "retry",
                    "target_id": target.target_id,
                    "query_name": name,
                    "query_path": str(query_path),
                    "attempt": attempt + 1,
                },
            )

        if not compiled:
            failed_count += 1

        compile_records.append(
            {
                "query_name": name,
                "purpose": purpose,
                "query_path": str(query_path),
                "compiled": compiled,
                "attempts": attempts,
            }
        )

    write_json(
        compile_results_path,
        {
            "target_id": target.target_id,
            "compiled_queries": compile_records,
        },
    )

    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "codex_ql",
            "event": "complete",
            "target_id": target.target_id,
            "generated_queries_total": len(queries),
            "generated_queries_compiled": len(compiled_paths),
            "generated_queries_failed": failed_count,
            "generation_plan": str(generation_plan_path),
            "compile_results": str(compile_results_path),
        },
    )

    return {
        "compiled_query_paths": compiled_paths,
        "generated_queries_total": len(queries),
        "generated_queries_compiled": len(compiled_paths),
        "generated_queries_failed": failed_count,
        "generated_query_dir": str(target_dir),
    }


def run_analyze(
    *,
    run_id: str,
    runs_root: str,
    config: dict[str, Any],
    topology: str,
    max_rounds: int,
    codex_cli: str,
    claude_cli: str,
    codex_ql_enabled: bool,
    ql_max_queries: int,
    ql_max_retries: int,
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

    codeql_cfg = config.get("codeql", {})
    analysis_cfg = config.get("analysis", {})
    codex_ql_cfg = analysis_cfg.get("codex_ql", {})
    codex_ql_timeout_seconds = _normalize_timeout_seconds(
        codex_ql_cfg.get("timeout_seconds", 0),
        default=0,
    )
    append_event(events_path, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": "analyze",
        "event": "start",
        "run_id": run_id,
        "targets": len(targets),
        "topology": topology,
        "codex_ql_enabled": bool(codex_ql_enabled),
        "ql_max_queries": int(ql_max_queries),
        "ql_max_retries": int(ql_max_retries),
        "codex_ql_timeout_seconds": codex_ql_timeout_seconds,
    })
    default_exclude_patterns = [
        str(x)
        for x in analysis_cfg.get("exclude_primary_path_globs", _DEFAULT_EXCLUDE_PRIMARY_PATH_GLOBS)
        if str(x).strip()
    ]
    repo_root = Path(__file__).resolve().parents[2]
    prompt_path = Path(str(analysis_cfg.get("prompt_template_path", _DEFAULT_PROMPT_PATH)))
    if not prompt_path.is_absolute():
        prompt_path = repo_root / prompt_path
    if prompt_path.exists():
        prompt_template = prompt_path.read_text(encoding="utf-8")
    else:
        prompt_template = _DEFAULT_PROMPT_PATH.read_text(encoding="utf-8")

    ql_prompt_path = Path(
        str(
            codex_ql_cfg.get(
                "prompt_template_path",
                _DEFAULT_CODEX_QL_PROMPT_PATH,
            )
        )
    )
    if not ql_prompt_path.is_absolute():
        ql_prompt_path = repo_root / ql_prompt_path
    if ql_prompt_path.exists():
        codex_ql_prompt_template = ql_prompt_path.read_text(encoding="utf-8")
    else:
        codex_ql_prompt_template = _DEFAULT_CODEX_QL_PROMPT_PATH.read_text(encoding="utf-8")

    skill_references = [
        str((repo_root / "skills" / "findvuln-ingest" / "SKILL.md").resolve()),
        str((repo_root / "skills" / "findvuln-analyze" / "SKILL.md").resolve()),
        str((repo_root / "skills" / "findvuln-validate" / "SKILL.md").resolve()),
    ]

    timeout_seconds = int(analysis_cfg.get("model_timeout_seconds", 300))
    runner = ParallelRoundRunner(executor=CLIModelExecutor(timeout_seconds=timeout_seconds))
    codex_ql_executor = CLIModelExecutor(timeout_seconds=codex_ql_timeout_seconds)
    policy = AdjudicationPolicy(
        min_consensus_confidence=float(analysis_cfg.get("min_consensus_confidence", 0.60)),
        require_evidence=bool(analysis_cfg.get("require_evidence", True)),
    )

    # Keep v1 detect-only policy: no patch generation/apply.
    target_results: list[AnalyzeTargetResult] = []
    prior_analyze_path = run_paths["analyze"] / "analyze_result.json"
    for target in targets:
        effective_codex_ql_enabled = bool(codex_ql_enabled)
        codeql = CodeQLRunner(
            cli_path=codeql_cfg.get("cli_path", "codeql"),
            language=target.language,
            query_dir=codeql_cfg.get("custom_query_dir", "src/codeql/queries"),
            threads=int(codeql_cfg.get("threads", 4)),
            timeout=int(codeql_cfg.get("timeout_seconds", 7200)),
            query_mode="pack" if effective_codex_ql_enabled else target.scan_mode,
            build_command=codeql_cfg.get("build_command"),
        )

        generated_queries_total = 0
        generated_queries_compiled = 0
        generated_queries_failed = 0
        generated_query_dir = str(run_paths["codeql_generated"] / target.target_id)
        compiled_query_paths: list[str] = []

        if effective_codex_ql_enabled:
            try:
                profile_hint = detect_or_resolve(target.snapshot_root, target.language)
            except Exception as exc:
                append_event(
                    events_path,
                    {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "stage": "codex_ql",
                        "event": "complete",
                        "target_id": target.target_id,
                        "generated_queries_total": 0,
                        "generated_queries_compiled": 0,
                        "generated_queries_failed": 0,
                        "error": f"language_detection_failed: {exc}",
                    },
                )
            else:
                codex_ql_stats = _generate_and_compile_codex_queries(
                    run_paths=run_paths,
                    events_path=events_path,
                    target=target,
                    profile=profile_hint,
                    codex_cli=codex_cli,
                    executor=codex_ql_executor,
                    prompt_template=codex_ql_prompt_template,
                    max_queries=max(1, int(ql_max_queries)),
                    max_retries=max(0, int(ql_max_retries)),
                    exclude_patterns=target.exclude_paths if target.exclude_paths else default_exclude_patterns,
                    recent_findings=_load_recent_findings_context(prior_analyze_path, target.target_id),
                    skill_references=skill_references,
                    codeql=codeql,
                )
                compiled_query_paths = [str(x) for x in codex_ql_stats.get("compiled_query_paths", [])]
                generated_queries_total = int(codex_ql_stats.get("generated_queries_total", 0))
                generated_queries_compiled = int(codex_ql_stats.get("generated_queries_compiled", 0))
                generated_queries_failed = int(codex_ql_stats.get("generated_queries_failed", 0))
                generated_query_dir = str(codex_ql_stats.get("generated_query_dir", generated_query_dir))
        else:
            append_event(
                events_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "stage": "codex_ql",
                    "event": "complete",
                    "target_id": target.target_id,
                    "generated_queries_total": 0,
                    "generated_queries_compiled": 0,
                    "generated_queries_failed": 0,
                    "skipped": True,
                    "reason": "codex_ql_disabled",
                },
            )

        raw_findings, profile = codeql.analyze(target.snapshot_root, target.codeql_db_path)
        if compiled_query_paths:
            extra_findings: list[dict[str, Any]] = []
            for ql_path in compiled_query_paths:
                try:
                    sarif_path = codeql.run_query(target.codeql_db_path, str(ql_path))
                    for parsed in codeql.parse_sarif(sarif_path, language=profile.codeql_language):
                        extra_findings.append(parsed.to_dict())
                except Exception as exc:
                    append_event(
                        events_path,
                        {
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "stage": "codex_ql",
                            "event": "custom_query_run_failed",
                            "target_id": target.target_id,
                            "query_path": str(ql_path),
                            "error": str(exc),
                        },
                    )
            raw_findings = _dedup_findings(raw_findings + extra_findings)

        findings_total_raw = len(raw_findings)
        findings = filter_source_sink_chains(raw_findings)
        findings_total = len(findings)

        target_exclude_patterns = target.exclude_paths if target.exclude_paths else default_exclude_patterns
        findings, excluded_by_path = _filter_findings_by_primary_path(findings, target_exclude_patterns)
        findings_excluded_by_path = len(excluded_by_path)
        for excluded_finding, matched_pattern in excluded_by_path:
            chain = excluded_finding.get("chain", [])
            primary = chain[0] if chain else {}
            append_event(
                events_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "stage": "analyze",
                    "event": "finding_filtered",
                    "target_id": target.target_id,
                    "rule_id": str(excluded_finding.get("rule_id", "unknown")),
                    "primary_file": str(primary.get("file", "")),
                    "reason": "exclude_primary_path",
                    "matched_pattern": matched_pattern,
                },
            )

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
                findings_total_raw=findings_total_raw,
                findings_total=findings_total,
                findings_excluded_by_path=findings_excluded_by_path,
                findings_selected=len(analyses),
                generated_queries_total=generated_queries_total,
                generated_queries_compiled=generated_queries_compiled,
                generated_queries_failed=generated_queries_failed,
                generated_query_dir=generated_query_dir,
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
