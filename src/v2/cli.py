from __future__ import annotations

import argparse
import logging
import sys

from src.v2.analyze import run_analyze
from src.v2.config import load_config
from src.v2.ingest import run_ingest
from src.v2.poc_report import generate_poc_markdown_reports
from src.v2.validate import run_validate, run_validate_multishot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="FindVuln V2 - CLI-heavy parallel adjudication pipeline",
        prog="findvuln",
    )
    parser.add_argument(
        "--config",
        default="config/settings.yaml",
        help="Path to configuration file",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="Sync source and build scan bundle")
    p_ingest.add_argument("--manifest", required=True, help="Path to manifest (yaml/json)")
    p_ingest.add_argument("--run-id", required=True, help="Run identifier")

    p_analyze = sub.add_parser("analyze", help="Run CodeQL and analyze via parallel adjudication or Codex single-pass")
    p_analyze.add_argument("--run-id", required=True, help="Run identifier")
    p_analyze.add_argument(
        "--topology",
        default="parallel-adjudicated",
        choices=["parallel-adjudicated", "codex-single-pass"],
        help="Adjudication topology",
    )
    p_analyze.add_argument("--max-rounds", type=int, default=6, help="Max critique rounds per finding")
    p_analyze.add_argument("--codex-cli", default=None, help="Codex CLI command")
    p_analyze.add_argument("--claude-cli", default=None, help="Claude CLI command")
    p_analyze.add_argument(
        "--codex-ql",
        dest="codex_ql",
        action="store_true",
        default=None,
        help="Enable Codex-generated QL queries (default: config.analysis.codex_ql.enabled)",
    )
    p_analyze.add_argument(
        "--no-codex-ql",
        dest="codex_ql",
        action="store_false",
        help="Disable Codex-generated QL queries",
    )
    p_analyze.add_argument("--ql-max-queries", type=int, default=None, help="Max generated QL queries per target")
    p_analyze.add_argument("--ql-max-retries", type=int, default=None, help="Max compile-fix retries per query")

    p_validate = sub.add_parser("validate", help="Run validation and write final report")
    p_validate.add_argument("--run-id", required=True, help="Run identifier")
    p_validate.add_argument("--verify-runs", type=int, default=2, help="Verification runs per finding")
    p_validate.add_argument(
        "--strategy",
        default="auto",
        choices=["auto", "asan", "test_runner", "build_and_test", "skip"],
        help="Validation strategy override",
    )
    p_validate.add_argument(
        "--multi-shot",
        action="store_true",
        help="Enable Codex-driven multi-shot trigger and validation loop",
    )
    p_validate.add_argument(
        "--max-shots",
        type=int,
        default=None,
        help="Maximum multi-shot attempts per finding (defaults to config.validation.multishot_max_shots)",
    )
    p_validate.add_argument(
        "--codex-cli",
        default=None,
        help="Codex CLI command for multi-shot trigger generation",
    )
    p_validate.add_argument(
        "--poc-md",
        action="store_true",
        help="Generate Markdown PoC reports using Codex from validate artifacts",
    )
    p_validate.add_argument(
        "--poc-codex-cli",
        default=None,
        help="Codex CLI command for PoC Markdown report generation",
    )
    p_validate.add_argument(
        "--poc-max-findings",
        type=int,
        default=None,
        help="Maximum number of findings to render as PoC Markdown reports",
    )
    p_validate.add_argument(
        "--execution-owner",
        default=None,
        choices=["codex-host", "oracle"],
        help="Validation execution owner (default: config.validation.execution_owner)",
    )

    p_e2e = sub.add_parser("e2e", help="Run ingest -> analyze -> validate(multi-shot) -> PoC markdown")
    p_e2e.add_argument("--manifest", required=True, help="Path to manifest (yaml/json)")
    p_e2e.add_argument("--run-id", required=True, help="Run identifier")
    p_e2e.add_argument(
        "--topology",
        default="parallel-adjudicated",
        choices=["parallel-adjudicated", "codex-single-pass"],
        help="Adjudication topology",
    )
    p_e2e.add_argument("--max-rounds", type=int, default=6, help="Max critique rounds per finding")
    p_e2e.add_argument("--verify-runs", type=int, default=2, help="Verification runs target for validation")
    p_e2e.add_argument("--max-shots", type=int, default=None, help="Max multi-shot attempts")
    p_e2e.add_argument(
        "--strategy",
        default="auto",
        choices=["auto", "asan", "test_runner", "build_and_test", "skip"],
        help="Validation strategy override",
    )
    p_e2e.add_argument("--codex-cli", default=None, help="Codex CLI command")
    p_e2e.add_argument("--claude-cli", default=None, help="Claude CLI command")
    p_e2e.add_argument(
        "--execution-owner",
        default="codex-host",
        choices=["codex-host", "oracle"],
        help="Validation execution owner for multi-shot",
    )
    p_e2e.add_argument(
        "--poc-max-findings",
        type=int,
        default=None,
        help="Maximum number of findings to render as PoC Markdown reports",
    )
    p_e2e.add_argument(
        "--codex-ql",
        dest="codex_ql",
        action="store_true",
        default=None,
        help="Enable Codex-generated QL queries (default: config.analysis.codex_ql.enabled)",
    )
    p_e2e.add_argument(
        "--no-codex-ql",
        dest="codex_ql",
        action="store_false",
        help="Disable Codex-generated QL queries",
    )
    p_e2e.add_argument("--ql-max-queries", type=int, default=None, help="Max generated QL queries per target")
    p_e2e.add_argument("--ql-max-retries", type=int, default=None, help="Max compile-fix retries per query")

    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    parser = build_parser()
    args = parser.parse_args()
    cfg = load_config(args.config)
    runs_root = str(cfg.get("sync", {}).get("runs_root", ".findvuln/runs"))

    try:
        if args.command == "ingest":
            out = run_ingest(
                manifest_path=args.manifest,
                run_id=args.run_id,
                runs_root=runs_root,
                detect_only=True,
            )
            print(f"Scan bundle: {out}")
            return

        if args.command == "analyze":
            llm_cfg = cfg.get("llm", {})
            codex_ql_cfg = cfg.get("analysis", {}).get("codex_ql", {})
            codex_ql_enabled = (
                bool(args.codex_ql)
                if args.codex_ql is not None
                else bool(codex_ql_cfg.get("enabled", True))
            )
            out = run_analyze(
                run_id=args.run_id,
                runs_root=runs_root,
                config=cfg,
                topology=args.topology,
                max_rounds=args.max_rounds,
                codex_cli=args.codex_cli or str(llm_cfg.get("codex_cli", "codex")),
                claude_cli=args.claude_cli or str(llm_cfg.get("claude_cli", "claude")),
                codex_ql_enabled=codex_ql_enabled,
                ql_max_queries=int(args.ql_max_queries or codex_ql_cfg.get("max_queries", 6)),
                ql_max_retries=int(args.ql_max_retries or codex_ql_cfg.get("max_retries", 2)),
            )
            print(f"Analyze result: {out}")
            return

        if args.command == "validate":
            llm_cfg = cfg.get("llm", {})
            validation_cfg = cfg.get("validation", {})
            execution_owner = args.execution_owner or str(validation_cfg.get("execution_owner", "codex-host"))
            if args.multi_shot:
                json_report, html_report = run_validate_multishot(
                    run_id=args.run_id,
                    runs_root=runs_root,
                    config=cfg,
                    verify_runs=args.verify_runs,
                    strategy=args.strategy,
                    max_shots=args.max_shots or int(validation_cfg.get("multishot_max_shots", 6)),
                    codex_cli=args.codex_cli or str(llm_cfg.get("codex_cli", "codex exec -")),
                    execution_owner=execution_owner,
                )
            else:
                json_report, html_report = run_validate(
                    run_id=args.run_id,
                    runs_root=runs_root,
                    config=cfg,
                    verify_runs=args.verify_runs,
                    strategy=args.strategy,
                    execution_owner=execution_owner,
                )
            print(f"JSON report: {json_report}")
            print(f"HTML report: {html_report}")

            poc_cfg = cfg.get("poc_report", {})
            should_write_poc = bool(args.poc_md or poc_cfg.get("enabled", False))
            if should_write_poc:
                poc_index, report_count = generate_poc_markdown_reports(
                    run_id=args.run_id,
                    runs_root=runs_root,
                    config=cfg,
                    codex_cli=args.poc_codex_cli or str(llm_cfg.get("codex_cli", "codex exec -")),
                    max_findings=args.poc_max_findings,
                )
                print(f"PoC index: {poc_index}")
                print(f"PoC reports generated: {report_count}")
            return

        if args.command == "e2e":
            llm_cfg = cfg.get("llm", {})
            analysis_cfg = cfg.get("analysis", {})
            codex_ql_cfg = analysis_cfg.get("codex_ql", {})
            validation_cfg = cfg.get("validation", {})
            codex_ql_enabled = (
                bool(args.codex_ql)
                if args.codex_ql is not None
                else bool(codex_ql_cfg.get("enabled", True))
            )

            bundle = run_ingest(
                manifest_path=args.manifest,
                run_id=args.run_id,
                runs_root=runs_root,
                detect_only=True,
            )
            print(f"Scan bundle: {bundle}")

            analyze_result = run_analyze(
                run_id=args.run_id,
                runs_root=runs_root,
                config=cfg,
                topology=args.topology or str(analysis_cfg.get("topology", "parallel-adjudicated")),
                max_rounds=int(args.max_rounds or int(analysis_cfg.get("max_rounds", 6))),
                codex_cli=args.codex_cli or str(llm_cfg.get("codex_cli", "codex")),
                claude_cli=args.claude_cli or str(llm_cfg.get("claude_cli", "claude")),
                codex_ql_enabled=codex_ql_enabled,
                ql_max_queries=int(args.ql_max_queries or codex_ql_cfg.get("max_queries", 6)),
                ql_max_retries=int(args.ql_max_retries or codex_ql_cfg.get("max_retries", 2)),
            )
            print(f"Analyze result: {analyze_result}")

            json_report, html_report = run_validate_multishot(
                run_id=args.run_id,
                runs_root=runs_root,
                config=cfg,
                verify_runs=int(args.verify_runs or int(validation_cfg.get("verify_runs", 2))),
                strategy=args.strategy,
                max_shots=args.max_shots or int(validation_cfg.get("multishot_max_shots", 6)),
                codex_cli=args.codex_cli or str(llm_cfg.get("codex_cli", "codex exec -")),
                execution_owner=args.execution_owner or str(validation_cfg.get("execution_owner", "codex-host")),
            )
            print(f"JSON report: {json_report}")
            print(f"HTML report: {html_report}")

            poc_index, report_count = generate_poc_markdown_reports(
                run_id=args.run_id,
                runs_root=runs_root,
                config=cfg,
                codex_cli=args.codex_cli or str(llm_cfg.get("codex_cli", "codex exec -")),
                max_findings=args.poc_max_findings,
            )
            if report_count == 0:
                print("PoC reports generated: 0 (no confirmed/probable findings)")
            else:
                print(f"PoC index: {poc_index}")
                print(f"PoC reports generated: {report_count}")
            return

        parser.error(f"Unknown command: {args.command}")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
