---
name: findvuln-multishot-validate
description: Codex-driven multi-shot vulnerability triggering and validation for FindVuln V2. Use when a task needs repeated trigger attempts from Codex, iterative sandbox validation, live progress report updates, and final status assignment from accumulated validation evidence.
---

# findvuln-multishot-validate

1. Load `analyze_result.json` and select consensus-vulnerable findings.
2. For each finding, ask Codex to emit one trigger plan JSON per shot.
3. Accept trigger plan modes:
   - `execution_target=host_docker` + `prepare_commands[]` + `verify_command` + `expected_signal` (codex-host mode)
   - `trigger_kind=command|pov_stdin|none` (oracle compatibility mode)
4. Execute each shot and capture `ValidationEvidence`.
   - codex-host: run commands on host with snapshot root as cwd
   - oracle: use sandbox oracle runtime/test strategies
5. Update live progress output after each shot in `validate/multishot_live_report.json`.
6. Stop early if required positive evidence is reached or cannot be reached.
7. Treat `expected_signal` match as positive evidence in codex-host mode.
8. Enforce real verification guard:
   - reject `strategy=skip`
   - fail run when consensus-vulnerable finding has no executed shot evidence
9. Resolve final status from cumulative evidence:
   - `confirmed`: positive evidence count reaches threshold
   - `probable`: at least one positive evidence but below threshold
   - `rejected`: no positive evidence with clean runtime outcomes
   - `needs-human-review`: unresolved or technical failures
10. Write final reports (`final_report.json`, `final_report.html`) and event logs.
11. If disclosure-ready output is needed, run with `--poc-md` to generate Markdown PoC reports for `confirmed`/`probable`.
