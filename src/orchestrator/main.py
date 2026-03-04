"""
Phase 5 – Orchestrator & Feedback Loop.

Pipeline:  Phase 2 (CodeQL) → Phase 1 (RAG lookup) → Phase 3 (LLM Patch)
           → Phase 4 (Sandbox Verify) → [Feedback Loop if failed]

Supports multi-language analysis: language auto-detection, CodeQL built-in
security packs, and language-specific sandbox verification.
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.panel import Panel

from src.lang_detect import LanguageProfile, detect_or_resolve
from src.rag.ingest import VulnKnowledgeBase
from src.codeql.wrapper import CodeQLRunner, summarize_chain, re_infer_actions, filter_source_sink_chains
from src.agent.agent import PatchAgent, format_rag_context, validate_diff
from src.sandbox.oracle import SandboxOracle, Verdict
from src.report.generator import generate_reports

logger = logging.getLogger(__name__)
console = Console()


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PipelineInput:
    """Everything needed to run the full pipeline on a single target."""
    source_root: str            # path to target source tree
    codeql_db_path: str         # where to create / reuse the CodeQL DB
    source_file: str | None = None  # the specific vulnerable file (optional for multi-lang)
    pov_file: str | None = None     # PoV input for the sandbox
    language: str = "auto"          # language override or "auto"
    scan_mode: str = "pack"         # "pack" (built-in) | "custom" (local .ql)
    extra_files: dict[str, str] = field(default_factory=dict)


@dataclass
class PipelineResult:
    success: bool
    attempts: int
    final_diff: str
    verdict: str
    language: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _enrich_snippets(
    results: list[dict[str, Any]],
    source_root: str,
) -> list[dict[str, Any]]:
    """Fill empty snippets in CodeQL results by reading source files."""
    file_cache: dict[str, list[str]] = {}
    root = Path(source_root)

    for result in results:
        for step in result.get("chain", []):
            if step.get("snippet"):
                continue
            rel_path = step.get("file", "")
            line = step.get("line", 0)
            if not rel_path or line <= 0:
                continue
            if rel_path not in file_cache:
                full_path = root / rel_path
                if full_path.is_file():
                    try:
                        file_cache[rel_path] = full_path.read_text(errors="replace").splitlines()
                    except Exception:
                        file_cache[rel_path] = []
                else:
                    file_cache[rel_path] = []
            lines = file_cache[rel_path]
            if 0 < line <= len(lines):
                step["snippet"] = lines[line - 1].strip()

    return results


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """Top-level controller that chains all five phases."""

    def __init__(self, config_path: str = "config/settings.yaml"):
        with open(config_path) as f:
            self.cfg = yaml.safe_load(f)

        # Phase 1
        rag_cfg = self.cfg["rag"]
        self.kb = VulnKnowledgeBase(
            persist_directory=rag_cfg["vectordb_path"],
            collection_name=rag_cfg["collection_name"],
            embedding_model=rag_cfg["embedding_model"],
            chunk_size=rag_cfg["chunk_size"],
            chunk_overlap=rag_cfg["chunk_overlap"],
            openai_api_key=rag_cfg.get("openai_api_key"),
        )

        # Phase 2
        cq_cfg = self.cfg["codeql"]
        self.codeql = CodeQLRunner(
            cli_path=cq_cfg["cli_path"],
            language=cq_cfg.get("language", "auto"),
            query_dir=cq_cfg.get("custom_query_dir", cq_cfg.get("query_suite", "src/codeql/queries")),
            threads=cq_cfg["threads"],
            timeout=cq_cfg["timeout_seconds"],
            query_mode=cq_cfg.get("query_mode", "pack"),
            build_command=cq_cfg.get("build_command"),
        )

        # Phase 3
        ag_cfg = self.cfg["agent"]
        self.agent = PatchAgent(
            provider=ag_cfg["provider"],
            model=ag_cfg["model"],
            temperature=ag_cfg["temperature"],
            max_tokens=ag_cfg["max_tokens"],
            anthropic_api_key=ag_cfg.get("anthropic_api_key"),
            openai_api_key=ag_cfg.get("openai_api_key"),
        )

        # Phase 4
        sb_cfg = self.cfg["sandbox"]
        self.oracle = SandboxOracle(
            timeout=sb_cfg["timeout_seconds"],
            asan_flags=sb_cfg["asan_flags"],
            compiler=sb_cfg["compiler"],
            verification_strategy=sb_cfg.get("verification_strategy", "auto"),
        )

        self.max_retries = self.cfg["orchestrator"]["max_feedback_loops"]

    # -- main pipeline ------------------------------------------------------

    def run(self, inp: PipelineInput) -> PipelineResult:
        history: list[dict[str, Any]] = []

        # ── Phase 2: Static Analysis ──────────────────────────────────────
        console.print(Panel("[bold cyan]Phase 2:[/] Running CodeQL analysis …"))

        # Override language if specified in input
        if inp.language != "auto":
            self.codeql.language = inp.language
        if inp.scan_mode:
            self.codeql.query_mode = inp.scan_mode

        codeql_results, profile = self.codeql.analyze(inp.source_root, inp.codeql_db_path)

        console.print(f"  Language: [bold]{profile.display_name}[/]")

        if not codeql_results:
            console.print("[yellow]No findings from CodeQL. Nothing to patch.[/]")
            return PipelineResult(
                success=True, attempts=0, final_diff="", verdict="no_findings",
                language=profile.display_name, history=history,
            )

        console.print(f"  Found {len(codeql_results)} finding(s).")
        logger.info("CodeQL results:\n%s", json.dumps(codeql_results, indent=2))

        # ── Determine source file(s) to read ─────────────────────────────
        source_file = inp.source_file
        affected_files = list({
            step["file"]
            for result in codeql_results
            for step in result.get("chain", [])
            if step.get("file")
        })

        if source_file is None:
            if affected_files:
                source_file = str(Path(inp.source_root) / affected_files[0])
                console.print(f"  Auto-selected source file: {source_file}")
            else:
                console.print("[yellow]No source files identified in findings.[/]")
                return PipelineResult(
                    success=False, attempts=0, final_diff="",
                    verdict="no_source_file",
                    language=profile.display_name, history=history,
                )

        # ── Enrich: fill empty snippets from source files ─────────────────
        codeql_results = _enrich_snippets(codeql_results, inp.source_root)

        # ── Re-infer actions now that snippets are populated ─────────────
        codeql_results = re_infer_actions(codeql_results, language=profile.codeql_language)

        # ── Preserve ALL enriched findings for the report ────────────────
        all_findings_enriched = copy.deepcopy(codeql_results)

        # ── Filter to source→sink chains only ────────────────────────────
        pre_filter_count = len(codeql_results)
        codeql_results = filter_source_sink_chains(codeql_results)
        console.print(
            f"  Source→sink filter: {len(codeql_results)}/{pre_filter_count} findings have complete chains."
        )

        if not codeql_results:
            console.print("[yellow]No findings with complete source→sink chains. Nothing to patch.[/]")
            result = PipelineResult(
                success=True, attempts=0, final_diff="", verdict="no_exploitable_findings",
                language=profile.display_name, history=[],
            )
            # Generate report with all findings (marked as filtered)
            finding_statuses = {i: "filtered" for i in range(len(all_findings_enriched))}
            try:
                json_rpt, html_rpt = generate_reports(
                    all_findings=all_findings_enriched,
                    finding_statuses=finding_statuses,
                    selected_indices=[],
                    rag_hits=[],
                    profile=profile,
                    pipeline_result=result,
                    inp=inp,
                    output_dir=inp.source_root,
                )
                console.print(f"  [green]Findings report: {json_rpt}[/]")
                console.print(f"  [green]HTML report: {html_rpt}[/]")
            except Exception as exc:
                logger.warning("Report generation failed: %s", exc)
            return result
        finding_statuses: dict[int, str] = {}
        selected_indices: list[int] = []

        # ── Deduplicate and limit findings for LLM ────────────────────────
        # Skip CI/test infrastructure files, prioritize main source code
        _CI_PREFIXES = (".evergreen/", "test/", "tests/", ".ci/", ".github/")
        severity_order = {"error": 0, "warning": 1, "note": 2}

        def _finding_sort_key(r: dict) -> tuple:
            pf = r["chain"][0]["file"] if r.get("chain") else ""
            is_ci = any(pf.startswith(p) for p in _CI_PREFIXES)
            sev = severity_order.get(r.get("severity", "note"), 9)
            chain_len = len(r.get("chain", []))
            return (is_ci, sev, chain_len)

        codeql_results.sort(key=_finding_sort_key)

        # Build index mapping: sorted position → original enriched index
        _original_indices: dict[int, int] = {}
        for sorted_idx, r in enumerate(codeql_results):
            for orig_idx, orig in enumerate(all_findings_enriched):
                if orig.get("rule_id") == r.get("rule_id") and orig.get("message") == r.get("message"):
                    chain_a = orig.get("chain", [])
                    chain_b = r.get("chain", [])
                    if chain_a and chain_b and chain_a[0].get("file") == chain_b[0].get("file"):
                        if orig_idx not in _original_indices.values():
                            _original_indices[sorted_idx] = orig_idx
                            break

        seen_rules: set[str] = set()
        limited_results: list[dict[str, Any]] = []
        for sorted_idx, r in enumerate(codeql_results):
            orig_idx = _original_indices.get(sorted_idx, sorted_idx)
            # Summarize long chains to keep prompt manageable while
            # preserving source/sink and key action nodes
            if len(r.get("chain", [])) > 6:
                r["chain"] = summarize_chain(r["chain"], max_steps=6)
            primary_file = r["chain"][0]["file"] if r.get("chain") else ""
            key = f"{r['rule_id']}:{primary_file}"
            if key not in seen_rules:
                seen_rules.add(key)
                limited_results.append(r)
                selected_indices.append(orig_idx)
                finding_statuses[orig_idx] = "attempted"
            else:
                finding_statuses[orig_idx] = "skipped"
            if len(limited_results) >= 5:
                break

        # Mark remaining unprocessed findings
        for idx in range(len(all_findings_enriched)):
            if idx not in finding_statuses:
                finding_statuses[idx] = "unprocessed"

        console.print(
            f"  Selected {len(limited_results)}/{len(codeql_results)} unique findings for LLM."
        )

        # ── Build combined source context from affected files ─────────────
        # Collect unique files referenced by the selected findings only
        limited_files = list(dict.fromkeys(
            step["file"]
            for r in limited_results
            for step in r.get("chain", [])
            if step.get("file")
        ))
        source_parts: list[str] = []
        total_chars = 0
        max_total = 20000  # keep prompt under LLM context limit
        for rel_path in limited_files:
            full_path = Path(inp.source_root) / rel_path
            if full_path.is_file():
                try:
                    content = full_path.read_text(errors="replace")
                    if len(content) > 6000:
                        content = content[:6000] + "\n... (truncated)"
                    if total_chars + len(content) > max_total:
                        break
                    # Use plain text separator (no nested code fences)
                    source_parts.append(
                        f"===== {rel_path} =====\n{content}"
                    )
                    total_chars += len(content)
                except Exception:
                    pass
        source_code = "\n\n".join(source_parts) if source_parts else Path(source_file).read_text()

        # ── Phase 1: RAG Lookup ───────────────────────────────────────────
        console.print(Panel("[bold cyan]Phase 1:[/] Querying RAG knowledge base …"))
        rag_query_text = Path(source_file).read_text(errors="replace")[:4000]
        rag_hits = self.kb.query(rag_query_text, top_k=self.cfg["rag"]["top_k"])
        rag_context = format_rag_context(rag_hits)
        console.print(f"  Retrieved {len(rag_hits)} relevant past patches.")

        # ── Phase 3: Initial Patch Generation ─────────────────────────────
        console.print(Panel("[bold cyan]Phase 3:[/] Generating patch via LLM …"))
        diff_text = self.agent.generate_patch(
            limited_results,
            rag_context,
            source_code,
            language_name=profile.display_name,
            code_fence=profile.code_fence,
        )

        # Collect allowed file paths from the CodeQL results
        allowed_files = list({
            step["file"]
            for result in codeql_results
            for step in result.get("chain", [])
            if step.get("file")
        })
        warnings = validate_diff(diff_text, allowed_files)
        if warnings:
            console.print(f"  [yellow]Diff warnings: {warnings}[/]")

        # ── Skip verification when LLM cannot generate a valid diff ───────
        if diff_text.startswith("ERROR:"):
            console.print(
                "[yellow]LLM could not generate a patch — "
                "skipping verification and generating report-only.[/]"
            )
            history.append({
                "attempt": 0,
                "diff": diff_text,
                "verdict": "skipped",
                "exit_code": 0,
                "asan_report": "",
            })

            result = PipelineResult(
                success=True,
                attempts=0,
                final_diff="",
                verdict="skipped",
                language=profile.display_name,
                history=history,
            )

            try:
                json_rpt, html_rpt = generate_reports(
                    all_findings=all_findings_enriched,
                    finding_statuses=finding_statuses,
                    selected_indices=selected_indices,
                    rag_hits=rag_hits,
                    profile=profile,
                    pipeline_result=result,
                    inp=inp,
                    output_dir=inp.source_root,
                )
                console.print(f"  [green]Findings report: {json_rpt}[/]")
                console.print(f"  [green]HTML report: {html_rpt}[/]")
            except Exception as exc:
                logger.warning("Report generation failed: %s", exc)

            return result

        # ── Phase 4 + Feedback Loop ───────────────────────────────────────
        for attempt in range(1, self.max_retries + 1):
            console.print(Panel(
                f"[bold cyan]Phase 4:[/] Sandbox verification – attempt {attempt}/{self.max_retries}"
            ))

            # Write diff to temp file
            diff_path = Path(tempfile.mktemp(suffix=".diff"))
            diff_path.write_text(diff_text)

            oracle_result = self.oracle.run(
                source_file=source_file if profile.sandbox_strategy == "asan" else None,
                pov_file=inp.pov_file,
                patch_file=str(diff_path),
                extra_files=inp.extra_files or None,
                language_profile=profile,
                project_root=inp.source_root,
            )

            history.append({
                "attempt": attempt,
                "diff": diff_text,
                "verdict": oracle_result.verdict.value,
                "exit_code": oracle_result.exit_code,
                "asan_report": oracle_result.asan_report,
            })

            console.print(
                f"  Verdict: [{'green' if oracle_result.verdict == Verdict.PASS else 'red'}]"
                f"{oracle_result.verdict.value}[/]  (exit={oracle_result.exit_code})"
            )

            if oracle_result.verdict in (Verdict.PASS, Verdict.SKIPPED):
                # Save the successful diff
                output_diff = Path(inp.source_root) / "patch.diff"
                output_diff.write_text(diff_text)
                console.print(f"  [green]Patch saved to {output_diff}[/]")

                # Upgrade selected findings to "patched"
                for idx in selected_indices:
                    finding_statuses[idx] = "patched"

                result = PipelineResult(
                    success=True,
                    attempts=attempt,
                    final_diff=diff_text,
                    verdict=oracle_result.verdict.value,
                    language=profile.display_name,
                    history=history,
                )

                # Generate vulnerability reports
                try:
                    json_rpt, html_rpt = generate_reports(
                        all_findings=all_findings_enriched,
                        finding_statuses=finding_statuses,
                        selected_indices=selected_indices,
                        rag_hits=rag_hits,
                        profile=profile,
                        pipeline_result=result,
                        inp=inp,
                        output_dir=inp.source_root,
                    )
                    console.print(f"  [green]Findings report: {json_rpt}[/]")
                    console.print(f"  [green]HTML report: {html_rpt}[/]")
                except Exception as exc:
                    logger.warning("Report generation failed: %s", exc)

                return result

            # ── Feedback: send error back to LLM ─────────────────────────
            if attempt < self.max_retries:
                error_type = oracle_result.verdict.value
                error_log = oracle_result.asan_report or oracle_result.stdout[-3000:]

                console.print(
                    f"  [yellow]Sending error feedback to LLM (retry {attempt + 1}) …[/]"
                )
                diff_text = self.agent.regenerate_patch(
                    error_type=error_type,
                    error_log=error_log,
                    codeql_json=codeql_results,
                    previous_diff=diff_text,
                )

                # If LLM still can't produce a valid diff, stop retrying
                if diff_text.startswith("ERROR:"):
                    console.print(
                        "[yellow]LLM still cannot generate a valid patch — "
                        "stopping retries.[/]"
                    )
                    break

        # Exhausted retries
        console.print("[bold red]All retry attempts exhausted. Patch failed.[/]")
        result = PipelineResult(
            success=False,
            attempts=self.max_retries,
            final_diff=diff_text,
            verdict=oracle_result.verdict.value,
            language=profile.display_name,
            history=history,
        )

        # Generate vulnerability reports even on failure
        try:
            json_rpt, html_rpt = generate_reports(
                all_findings=all_findings_enriched,
                finding_statuses=finding_statuses,
                selected_indices=selected_indices,
                rag_hits=rag_hits,
                profile=profile,
                pipeline_result=result,
                inp=inp,
                output_dir=inp.source_root,
            )
            console.print(f"  Findings report: {json_rpt}")
            console.print(f"  HTML report: {html_rpt}")
        except Exception as exc:
            logger.warning("Report generation failed: %s", exc)

        return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="FindVuln – Automated vulnerability analysis and patching pipeline.",
        prog="python -m src.orchestrator.main",
    )
    parser.add_argument(
        "source_root",
        help="Path to the target source tree (e.g., a cloned repo)",
    )
    parser.add_argument(
        "codeql_db_path",
        help="Path for the CodeQL database (created if needed)",
    )
    parser.add_argument(
        "--source-file", "-s",
        default=None,
        help="Specific source file to analyze (auto-detected from CodeQL results if omitted)",
    )
    parser.add_argument(
        "--pov-file", "-p",
        default=None,
        help="Path to PoV input file for C/C++ ASAN verification",
    )
    parser.add_argument(
        "--language", "-l",
        default="auto",
        help="Language override: auto, cpp, python, java, go, javascript, rust, ruby, csharp, swift",
    )
    parser.add_argument(
        "--scan", "--scan-mode",
        default="pack",
        choices=["pack", "custom"],
        help="Query mode: 'pack' (built-in security suite) or 'custom' (local .ql files)",
    )
    args = parser.parse_args()

    inp = PipelineInput(
        source_root=args.source_root,
        codeql_db_path=args.codeql_db_path,
        source_file=args.source_file,
        pov_file=args.pov_file,
        language=args.language,
        scan_mode=args.scan,
    )

    orch = Orchestrator()
    result = orch.run(inp)

    console.print("\n" + "=" * 60)
    console.print(Panel(
        f"[bold]Result:[/] {'[green]SUCCESS' if result.success else '[red]FAILED'}[/]\n"
        f"Language: {result.language}\n"
        f"Attempts: {result.attempts}\n"
        f"Final verdict: {result.verdict}",
        title="Pipeline Complete",
    ))

    # Write full report
    report_path = Path(inp.source_root) / "pipeline_report.json"
    report_path.write_text(json.dumps({
        "success": result.success,
        "language": result.language,
        "attempts": result.attempts,
        "verdict": result.verdict,
        "history": result.history,
    }, indent=2))
    console.print(f"Report: {report_path}")


if __name__ == "__main__":
    main()
