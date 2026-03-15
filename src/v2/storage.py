from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def run_dir(run_id: str, runs_root: str) -> Path:
    return Path(runs_root).resolve() / run_id


def ensure_run_layout(run_id: str, runs_root: str) -> dict[str, Path]:
    base = run_dir(run_id, runs_root)
    paths = {
        "base": base,
        "ingest": base / "ingest",
        "analyze": base / "analyze",
        "validate": base / "validate",
        "codeql_generated": base / "codeql_generated",
        "logs": base / "logs",
        "snapshots": base / "snapshots",
        "mirrors": base / "mirrors",
        "codeql_db": base / "codeql_db",
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    return paths


def append_event(log_path: Path, event: dict[str, Any]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=True) + "\n")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=True)


def read_json(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
