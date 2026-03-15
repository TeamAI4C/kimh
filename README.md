# FindVuln V2 - CLI-Heavy Parallel Adjudication

FindVuln V2 runs a detect-only pipeline with explicit stages:

1. `ingest`: source sync + snapshot + file index + CodeQL input bundle
2. `analyze`: CodeQL + parallel `Codex CLI` and `Claude CLI` adjudication loop
3. `validate`: runtime validation and final report generation
4. `validate --multi-shot`: Codex-triggered multi-shot verification loop with live report updates

The default policy is **detect_only=true** (no patch apply/commit/PR automation).

## Commands

```bash
findvuln ingest --manifest <manifest.yaml> --run-id <run_id>
findvuln analyze --run-id <run_id> --topology parallel-adjudicated --max-rounds 6 --codex-ql --ql-max-queries 6 --ql-max-retries 2
findvuln validate --run-id <run_id> --verify-runs 2 --strategy auto --execution-owner codex-host
```

Codex single-pass mode (Codex CLI only):

```bash
findvuln analyze --run-id <run_id> --topology codex-single-pass
```

Codex multi-shot verification mode:

```bash
findvuln validate --run-id <run_id> --multi-shot --max-shots 6 --strategy auto
```

Multi-shot behavior:

- Codex proposes per-shot trigger plans (`command` or `pov_stdin`)
- Codex host-direct mode is supported via `--execution-owner codex-host`
- For ASAN targets, Codex PoV control is enforced by default (`multishot_force_codex_pov_for_asan: true`)
- PoV artifacts are persisted under `.findvuln/runs/<run_id>/validate/pov_artifacts/...`

Codex Markdown PoC report generation:

```bash
findvuln validate --run-id <run_id> --multi-shot --max-shots 6 --strategy auto --poc-md
```

End-to-end single command:

```bash
findvuln e2e --manifest <manifest.yaml> --run-id <run_id>
```

`e2e` runs:
1. `ingest`
2. `analyze` (default `parallel-adjudicated`, `pack+custom` with Codex-generated QL on by default)
3. `validate --multi-shot --execution-owner codex-host`
4. `poc-md`

Analyze supports Codex QL generation controls:

- `--codex-ql` / `--no-codex-ql`
- `--ql-max-queries <N>` (default 6)
- `--ql-max-retries <N>` (default 2)
- `analysis.codex_ql.timeout_seconds` (`0` = no timeout, default `0`; set a positive value to enforce timeout)

Generated query artifacts:

- `.findvuln/runs/<run_id>/codeql_generated/<target_id>/generation_plan.json`
- `.findvuln/runs/<run_id>/codeql_generated/<target_id>/compile_results.json`
- `.findvuln/runs/<run_id>/codeql_generated/<target_id>/query-*.ql`

Codex QL response tracking events (`logs/events.jsonl`):

- `stage=codex_ql,event=model_request_start`
- `stage=codex_ql,event=model_request_complete` (elapsed ms, return code, stdout/stderr byte size)

Validation guardrails:

- `strategy=skip` is rejected for V2 real-verification runs
- consensus-vulnerable findings must contain at least one executed validation shot

PoC Markdown report sections follow a bug bounty style format:

- Descriptive Title
- Summary & Impact
- Affected Systems
- Steps to Reproduce (STR)
- Evidence (Proof)
- Remediation / Recommendation

Recommended Codex CLI baseline for V2:

```bash
codex exec --model gpt-5.3-codex -c 'reasoning_effort="xhigh"' --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -
```

Default prompt template path:

- `src/v2/prompts/codex_default_prompt.txt`
- `src/v2/prompts/codex_trigger_prompt.txt`

## Manifest (example)

```yaml
targets:
  - name: demo-cpp
    source_root: /absolute/path/to/repo
    language: cpp
    scan_mode: pack
    pov_file: /absolute/path/to/pov_input.txt
    exclude_paths:
      - "test/**"
      - "tests/**"
```

Supported target fields:

- `name`: label for the run target
- `source_root`: local repository path (or use `git_url`)
- `git_url`: remote git URL for mirror + snapshot sync
- `ref`: optional git ref/commit to checkout
- `language`: `auto|cpp|python|javascript|java|go|rust|ruby|csharp|swift`
- `scan_mode`: `pack|custom`
- `codeql_db_path`: optional override for CodeQL DB path
- `pov_file`: optional PoV input used by ASAN validation
- `exclude_paths`: optional path globs for filtering findings by `primary_file`

## Outputs

Run artifacts are written under:

- `.findvuln/runs/<run_id>/ingest/scan_bundle.json`
- `.findvuln/runs/<run_id>/analyze/analyze_result.json`
- `.findvuln/runs/<run_id>/validate/final_report.json`
- `.findvuln/runs/<run_id>/validate/final_report.html`
- `.findvuln/runs/<run_id>/validate/multishot_live_report.json` (when `--multi-shot`)
- `.findvuln/runs/<run_id>/validate/poc_reports/*/*.md` (when `--poc-md`)
- `.findvuln/runs/<run_id>/validate/poc_reports/poc_reports_index.json` (when `--poc-md`)
- `.findvuln/runs/<run_id>/logs/events.jsonl`

Final statuses are one of:

- `confirmed`
- `probable`
- `rejected`
- `needs-human-review`

## Prerequisites

- Python >= 3.10
- CodeQL CLI
- Docker (for sandbox validation)
- `codex` CLI and `claude` CLI installed/authenticated

## Legacy V1

The old monolithic pipeline is still available as:

```bash
findvuln-v1 ...
```
