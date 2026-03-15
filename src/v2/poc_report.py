from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.v2.llm_cli import CLIModelExecutor
from src.v2.storage import append_event, ensure_run_layout, read_json, write_json


@dataclass
class PoCReportRecord:
    target_id: str
    finding_id: str
    final_status: str
    report_path: str
    generator: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "finding_id": self.finding_id,
            "final_status": self.final_status,
            "report_path": self.report_path,
            "generator": self.generator,
        }


def _safe_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", name).strip("_") or "report"


def _strip_outer_code_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) < 3:
        return stripped
    if lines[-1].strip() != "```":
        return stripped
    return "\n".join(lines[1:-1]).strip()


def _render_poc_prompt(
    *,
    template: str,
    run_id: str,
    target_id: str,
    finding_id: str,
    finding: dict[str, Any],
    analyze_finding: dict[str, Any] | None,
    target_meta: dict[str, Any] | None,
    finding_events: list[dict[str, Any]],
) -> str:
    pov_artifacts = [
        str(v.get("pov_artifact", ""))
        for v in finding.get("validation_evidence", [])
        if isinstance(v, dict) and v.get("pov_artifact")
    ]
    pov_artifacts = [x for x in pov_artifacts if x]

    rendered = template
    rendered = rendered.replace("{{RUN_ID}}", run_id)
    rendered = rendered.replace("{{TARGET_ID}}", target_id)
    rendered = rendered.replace("{{FINDING_ID}}", finding_id)
    rendered = rendered.replace("{{FINAL_FINDING_JSON}}", json.dumps(finding, indent=2))
    rendered = rendered.replace("{{ANALYZE_FINDING_JSON}}", json.dumps(analyze_finding or {}, indent=2))
    rendered = rendered.replace("{{TARGET_META_JSON}}", json.dumps(target_meta or {}, indent=2))
    rendered = rendered.replace("{{EVENT_LOGS_JSON}}", json.dumps(finding_events, indent=2))
    rendered = rendered.replace("{{POV_ARTIFACTS_JSON}}", json.dumps(pov_artifacts, indent=2))
    return rendered


def _fallback_poc_markdown(
    *,
    run_id: str,
    target_id: str,
    target_meta: dict[str, Any] | None,
    finding: dict[str, Any],
    analyze_finding: dict[str, Any] | None,
    finding_events: list[dict[str, Any]],
    reason: str,
) -> str:
    title = (
        f"{finding.get('rule_id', 'Unknown Rule')} in "
        f"{finding.get('primary_file', 'unknown-file')}:{finding.get('primary_line', 0)} "
        f"({finding.get('final_status', 'unknown')})"
    )

    summary = analyze_finding.get("message") if isinstance(analyze_finding, dict) else None
    if not summary:
        summary = finding.get("message") or "Potential vulnerability candidate was identified."

    source_root = ""
    if isinstance(target_meta, dict):
        source_root = str(target_meta.get("original_source", ""))
    snapshot_root = ""
    if isinstance(target_meta, dict):
        snapshot_root = str(target_meta.get("snapshot_root", ""))

    evidence = finding.get("validation_evidence", [])
    event_tail = finding_events[-6:] if finding_events else []

    return (
        f"# {title}\n\n"
        "## Summary & Impact\n"
        f"{summary}\n\n"
        f"Current status is `{finding.get('final_status', 'unknown')}` with evidence score "
        f"`{finding.get('evidence_score', 0.0)}`. Potential impact includes unauthorized access, "
        "data exposure, or integrity compromise depending on exploitability.\n\n"
        "## Affected Systems\n"
        f"- Run ID: `{run_id}`\n"
        f"- Target ID: `{target_id}`\n"
        f"- Source Root: `{source_root or 'Unknown'}`\n"
        f"- Snapshot Root: `{snapshot_root or 'Unknown'}`\n"
        f"- Location: `{finding.get('primary_file', 'unknown-file')}:{finding.get('primary_line', 0)}`\n"
        f"- Rule: `{finding.get('rule_id', 'unknown')}`\n\n"
        "## Steps to Reproduce (STR)\n"
        "1. Prepare the exact repository snapshot used in this run.\n"
        "2. Re-run analysis and validation for the target and finding ID.\n"
        "3. Execute the trigger command or stdin PoV artifacts listed in Evidence.\n"
        "4. Observe validation verdicts, stderr/stdout tails, and sanitizer/test failure signals.\n\n"
        "## Evidence\n"
        "### Validation Evidence\n"
        "```json\n"
        f"{json.dumps(evidence, indent=2)}\n"
        "```\n\n"
        "### Event Log Excerpts\n"
        "```json\n"
        f"{json.dumps(event_tail, indent=2)}\n"
        "```\n\n"
        "## Remediation / Recommendation\n"
        "1. Add strict input validation and boundary checks around the affected code path.\n"
        "2. Enforce safe defaults and reject malformed/untrusted payloads.\n"
        "3. Add regression tests that replay the PoV trigger and assert non-exploitability.\n\n"
        "## Notes\n"
        f"- This report was generated using fallback mode because Codex output was unavailable: `{reason}`\n"
    )


def _build_events_index(events_path: Path, keep_per_finding: int = 40) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    if not events_path.exists():
        return out

    with open(events_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            finding_id = event.get("finding_id")
            if not finding_id:
                continue
            key = str(finding_id)
            bucket = out.setdefault(key, [])
            bucket.append(event)
            if len(bucket) > keep_per_finding:
                del bucket[0 : len(bucket) - keep_per_finding]
    return out


def generate_poc_markdown_reports(
    *,
    run_id: str,
    runs_root: str,
    config: dict[str, Any],
    codex_cli: str,
    max_findings: int | None = None,
) -> tuple[str, int]:
    run_paths = ensure_run_layout(run_id, runs_root)
    events_path = run_paths["logs"] / "events.jsonl"

    reporting_cfg = config.get("reporting", {})
    poc_cfg = config.get("poc_report", {})
    analysis_cfg = config.get("analysis", {})

    report_json = run_paths["validate"] / str(reporting_cfg.get("json_name", "final_report.json"))
    if not report_json.exists():
        raise RuntimeError(f"Final report not found: {report_json}")

    final_report = read_json(report_json)
    analyze_path = run_paths["analyze"] / "analyze_result.json"
    analyze = read_json(analyze_path) if analyze_path.exists() else {}

    bundle_path = run_paths["ingest"] / "scan_bundle.json"
    bundle = read_json(bundle_path) if bundle_path.exists() else {}

    include_statuses = poc_cfg.get(
        "include_statuses",
        ["confirmed", "probable"],
    )
    include_statuses = {str(x) for x in include_statuses}
    include_statuses = include_statuses & {"confirmed", "probable"}
    if not include_statuses:
        include_statuses = {"confirmed", "probable"}

    max_reports = int(max_findings if max_findings is not None else poc_cfg.get("max_findings", 50))
    max_reports = max(1, max_reports)

    timeout = int(poc_cfg.get("timeout_seconds", analysis_cfg.get("model_timeout_seconds", 300)))
    executor = CLIModelExecutor(timeout_seconds=timeout)

    repo_root = Path(__file__).resolve().parents[2]
    prompt_path = Path(str(poc_cfg.get("prompt_template_path", "src/v2/prompts/codex_poc_report_prompt.txt")))
    if not prompt_path.is_absolute():
        prompt_path = repo_root / prompt_path
    if not prompt_path.exists():
        raise RuntimeError(f"PoC prompt template not found: {prompt_path}")
    prompt_template = prompt_path.read_text(encoding="utf-8")

    output_dirname = str(poc_cfg.get("output_dirname", "poc_reports"))
    output_root = run_paths["validate"] / output_dirname
    output_root.mkdir(parents=True, exist_ok=True)

    analyze_map: dict[tuple[str, str], dict[str, Any]] = {}
    for t in analyze.get("targets", []):
        tid = str(t.get("target_id", ""))
        for f in t.get("findings", []):
            analyze_map[(tid, str(f.get("finding_id", "")))] = f

    target_meta_map = {str(t.get("target_id", "")): t for t in bundle.get("targets", []) if isinstance(t, dict)}
    events_index = _build_events_index(events_path)

    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "poc_report",
            "event": "start",
            "run_id": run_id,
            "max_findings": max_reports,
            "include_statuses": sorted(include_statuses),
        },
    )

    records: list[PoCReportRecord] = []
    for t in final_report.get("targets", []):
        target_id = str(t.get("target_id", ""))
        target_dir = output_root / _safe_name(target_id)
        target_dir.mkdir(parents=True, exist_ok=True)

        for finding in t.get("final_findings", []):
            if len(records) >= max_reports:
                break

            finding_id = str(finding.get("finding_id", ""))
            final_status = str(finding.get("final_status", "unknown"))
            if final_status not in include_statuses:
                continue

            analyze_finding = analyze_map.get((target_id, finding_id))
            target_meta = target_meta_map.get(target_id)
            finding_events = events_index.get(finding_id, [])
            prompt = _render_poc_prompt(
                template=prompt_template,
                run_id=run_id,
                target_id=target_id,
                finding_id=finding_id,
                finding=finding,
                analyze_finding=analyze_finding,
                target_meta=target_meta,
                finding_events=finding_events,
            )

            raw = executor.run("codex", codex_cli, prompt)
            if raw.ok and raw.stdout.strip():
                markdown = _strip_outer_code_fence(raw.stdout)
                generator = "codex"
                reason = ""
            else:
                reason = raw.error or raw.stderr or "empty-output"
                markdown = _fallback_poc_markdown(
                    run_id=run_id,
                    target_id=target_id,
                    target_meta=target_meta,
                    finding=finding,
                    analyze_finding=analyze_finding,
                    finding_events=finding_events,
                    reason=reason[-300:],
                )
                generator = "fallback"

            report_path = target_dir / f"{_safe_name(finding_id)}.md"
            report_path.write_text(markdown.rstrip() + "\n", encoding="utf-8")

            rec = PoCReportRecord(
                target_id=target_id,
                finding_id=finding_id,
                final_status=final_status,
                report_path=str(report_path),
                generator=generator,
            )
            records.append(rec)

            append_event(
                events_path,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "stage": "poc_report",
                    "event": "finding_report_generated",
                    "target_id": target_id,
                    "finding_id": finding_id,
                    "final_status": final_status,
                    "generator": generator,
                    "report_path": str(report_path),
                    "codex_error": reason[-300:] if reason else "",
                },
            )

        if len(records) >= max_reports:
            break

    index_payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reports": [r.to_dict() for r in records],
    }
    index_path = output_root / "poc_reports_index.json"
    write_json(index_path, index_payload)

    append_event(
        events_path,
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "poc_report",
            "event": "complete",
            "generated_reports": len(records),
            "index_path": str(index_path),
            "skip_reason": "no findings matched include_statuses" if not records else "",
        },
    )

    return str(index_path), len(records)
