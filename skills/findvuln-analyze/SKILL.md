---
name: findvuln-analyze
description: Codex/Claude adjudication for FindVuln V2. Use when a task needs CodeQL-driven vulnerability triage with either (1) parallel Codex+Claude rounds (`parallel-adjudicated`) or (2) Codex-only single pass (`codex-single-pass`), standardized `ModelVerdict` extraction, and consensus/dispute decisions.
---

# findvuln-analyze

1. Load `scan_bundle.json` and run CodeQL per target.
2. Generate target-scoped custom CodeQL queries via Codex (`analysis.codex_ql.enabled=true` by default).
   - Save under `.findvuln/runs/<run_id>/codeql_generated/<target_id>/`.
   - Compile each generated query (`codeql query compile`) before execution.
   - On compile failure, feed error back to Codex and retry up to configured limit.
   - Keep artifacts: `generation_plan.json`, `compile_results.json`, and codex_ql events.
3. Execute with `pack+custom` policy:
   - Always run built-in pack security queries.
   - Run only compile-passed generated `.ql` queries.
   - Merge and deduplicate findings across both sources.
4. Choose topology:
   - `parallel-adjudicated`: run Codex CLI and Claude CLI in parallel each round.
   - `codex-single-pass`: run only Codex CLI once per finding.
5. Use the default Codex baseline unless overridden:
   - `codex exec --model gpt-5.3-codex -c 'reasoning_effort="xhigh"' --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -`
6. Build prompts from `src/v2/prompts/codex_default_prompt.txt` and include skill references for:
   - `skills/findvuln-ingest/SKILL.md`
   - `skills/findvuln-analyze/SKILL.md`
   - `skills/findvuln-validate/SKILL.md`
7. Parse outputs into `ModelVerdict` JSON contract.
8. Apply rule-based adjudication (`consensus` or `dispute`).
9. On dispute, iterate critique loop up to configured max rounds.
10. Stop early on `consensus + sufficient evidence`.
11. If one model fails in two consecutive rounds, mark finding as `needs-human-review`.
12. Write `analyze_result.json` including adjudication history, model contribution counters, and generated-query stats.
