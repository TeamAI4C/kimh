---
name: findvuln-validate
description: Runtime validation and final status assignment for FindVuln V2. Use when a task needs sandbox verification for analyzed findings, evidence scoring, and final status resolution (`confirmed/probable/rejected/needs-human-review`) with JSON and HTML reports.
---

# findvuln-validate

1. Load `analyze_result.json` and map findings to target snapshots.
2. Run verification only for consensus-vulnerable findings.
3. Execute validator up to `verify_runs` times with language-aware strategy.
4. Record each run as `ValidationEvidence`.
5. Resolve final status:
   - `confirmed`: positive evidence in all runs
   - `probable`: partial positive evidence
   - `rejected`: consensus says non-vulnerable or no positive evidence with clean runs
   - `needs-human-review`: unresolved adjudication or technical validation failures
6. Write `final_report.json` and `final_report.html`.
7. Optionally generate bug-bounty style Markdown PoC reports from artifacts via Codex:
   - `findvuln validate --run-id <id> --poc-md`
8. For iterative trigger validation, switch to `findvuln-multishot-validate` workflow and run `findvuln validate --multi-shot`.
