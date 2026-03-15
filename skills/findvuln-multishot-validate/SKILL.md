---
name: findvuln-multishot-validate
description: Codex-driven multi-shot vulnerability triggering and validation for FindVuln V2. Use when a task needs repeated trigger attempts from Codex, iterative sandbox validation, live progress report updates, and final status assignment from accumulated validation evidence.
---

# findvuln-multishot-validate

1. Load `analyze_result.json` and select consensus-vulnerable findings.
2. For each finding, ask Codex to emit one trigger plan JSON per shot.
3. Accept trigger plan kinds:
   - `command`: run a custom command inside the sandbox
   - `pov_stdin`: generate a temporary PoV stdin file for ASAN runtime
   - `none`: stop attempts for this finding
4. Execute each shot in sandbox and capture `ValidationEvidence`.
5. Update live progress output after each shot in `validate/multishot_live_report.json`.
6. Stop early if required positive evidence is reached or cannot be reached.
7. Resolve final status from cumulative evidence:
   - `confirmed`: positive evidence count reaches threshold
   - `probable`: at least one positive evidence but below threshold
   - `rejected`: no positive evidence with clean runtime outcomes
   - `needs-human-review`: unresolved or technical failures
8. Write final reports (`final_report.json`, `final_report.html`) and event logs.
9. If disclosure-ready output is needed, run with `--poc-md` to generate Markdown PoC reports per finding.
