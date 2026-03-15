---
name: findvuln-ingest
description: Source synchronization and scan-bundle preparation for FindVuln V2. Use when a task needs repository sync (local path or git URL), commit pinning, snapshot creation, file indexing, and generation of `.findvuln/runs/RUN_ID/ingest/scan_bundle.json` before analysis.
---

# findvuln-ingest

1. Validate manifest schema (`targets[]`, source location, language, scan mode).
2. Sync source with git-aware flow:
   - remote: mirror fetch + snapshot clone + optional `ref` checkout
   - local git: fetch (best effort) + snapshot clone pinned to current commit
   - local non-git: copytree snapshot
3. Build file index from snapshot root.
4. Produce one `ScanTarget` per target and write `scan_bundle.json`.
5. Keep detect-only policy (`detect_only=true`) unchanged.
