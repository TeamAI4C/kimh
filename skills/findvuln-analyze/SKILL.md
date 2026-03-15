---
name: findvuln-analyze
description: Codex/Claude adjudication for FindVuln V2. Use when a task needs CodeQL-driven vulnerability triage with either (1) parallel Codex+Claude rounds (`parallel-adjudicated`) or (2) Codex-only single pass (`codex-single-pass`), standardized `ModelVerdict` extraction, and consensus/dispute decisions.
---

# findvuln-analyze

1. Load `scan_bundle.json` and run CodeQL per target.
2. Choose topology:
   - `parallel-adjudicated`: run Codex CLI and Claude CLI in parallel each round.
   - `codex-single-pass`: run only Codex CLI once per finding.
3. Use the default Codex baseline unless overridden:
   - `codex exec --model gpt-5.3-codex -c 'reasoning_effort="xhigh"' --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -`
4. Build prompts from `src/v2/prompts/codex_default_prompt.txt` and include skill references for:
   - `skills/findvuln-ingest/SKILL.md`
   - `skills/findvuln-analyze/SKILL.md`
   - `skills/findvuln-validate/SKILL.md`
5. Parse outputs into `ModelVerdict` JSON contract.
6. Apply rule-based adjudication (`consensus` or `dispute`).
7. On dispute, iterate critique loop up to configured max rounds.
8. Stop early on `consensus + sufficient evidence`.
9. If one model fails in two consecutive rounds, mark finding as `needs-human-review`.
10. Write `analyze_result.json` including adjudication history and per-model contribution counters.
