from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.v2.contracts import ScanBundle, ScanTarget
from src.v2.storage import append_event, ensure_run_layout, write_json

logger = logging.getLogger(__name__)


@dataclass
class TargetManifest:
    name: str
    source_root: str | None
    git_url: str | None
    ref: str | None
    language: str
    scan_mode: str
    codeql_db_path: str | None
    pov_file: str | None
    exclude_paths: list[str]


class IngestError(RuntimeError):
    pass


def _run(cmd: list[str], cwd: str | None = None) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if proc.returncode != 0:
        raise IngestError(f"Command failed ({' '.join(cmd)}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def _load_manifest(path: str) -> list[TargetManifest]:
    m_path = Path(path)
    if not m_path.exists():
        raise IngestError(f"Manifest not found: {m_path}")

    if m_path.suffix.lower() == ".json":
        data = json.loads(m_path.read_text())
    else:
        data = yaml.safe_load(m_path.read_text())

    if not isinstance(data, dict):
        raise IngestError("Manifest must be an object")

    raw_targets: list[dict[str, Any]]
    if isinstance(data.get("targets"), list):
        raw_targets = [t for t in data["targets"] if isinstance(t, dict)]
    else:
        raw_targets = [data]

    targets: list[TargetManifest] = []
    for i, t in enumerate(raw_targets, 1):
        name = str(t.get("name") or f"target-{i}")
        source_root = t.get("source_root")
        git_url = t.get("git_url")
        if not source_root and not git_url:
            raise IngestError(f"Target {name}: either source_root or git_url is required")
        raw_exclude_paths = t.get("exclude_paths", [])
        exclude_paths: list[str] = []
        if isinstance(raw_exclude_paths, list):
            exclude_paths = [str(x) for x in raw_exclude_paths if str(x).strip()]

        targets.append(
            TargetManifest(
                name=name,
                source_root=str(source_root) if source_root else None,
                git_url=str(git_url) if git_url else None,
                ref=str(t.get("ref")) if t.get("ref") else None,
                language=str(t.get("language", "auto")),
                scan_mode=str(t.get("scan_mode", "pack")),
                codeql_db_path=str(t.get("codeql_db_path")) if t.get("codeql_db_path") else None,
                pov_file=str(t.get("pov_file")) if t.get("pov_file") else None,
                exclude_paths=exclude_paths,
            )
        )
    return targets


def _build_file_index(snapshot_root: Path) -> list[str]:
    try:
        out = _run(["rg", "--files"], cwd=str(snapshot_root))
        files = [line.strip() for line in out.splitlines() if line.strip()]
        return sorted(files)
    except Exception:
        files: list[str] = []
        for p in snapshot_root.rglob("*"):
            if p.is_file():
                files.append(str(p.relative_to(snapshot_root)))
        return sorted(files)


def _sync_target(target: TargetManifest, run_paths: dict[str, Path], index: int) -> ScanTarget:
    target_id = f"{target.name}-{index:02d}"
    snapshot_root = run_paths["snapshots"] / target_id
    if snapshot_root.exists():
        shutil.rmtree(snapshot_root)

    commit: str | None = None

    if target.git_url:
        mirror = run_paths["mirrors"] / f"{target_id}.git"
        if not mirror.exists():
            _run(["git", "clone", "--mirror", target.git_url, str(mirror)])
        else:
            _run(["git", "-C", str(mirror), "fetch", "--all", "--tags", "--prune"])

        _run(["git", "clone", str(mirror), str(snapshot_root)])
        if target.ref:
            _run(["git", "-C", str(snapshot_root), "checkout", target.ref])
        commit = _run(["git", "-C", str(snapshot_root), "rev-parse", "HEAD"])
        original = target.git_url

    else:
        assert target.source_root is not None
        source = Path(target.source_root).resolve()
        if not source.exists():
            raise IngestError(f"Source path not found: {source}")

        git_dir = source / ".git"
        if git_dir.exists():
            # Best-effort sync from remotes before snapshot pinning.
            try:
                _run(["git", "-C", str(source), "fetch", "--all", "--tags", "--prune"])
            except Exception:
                logger.warning("git fetch failed for %s (continuing)", source)

            commit = _run(["git", "-C", str(source), "rev-parse", "HEAD"])
            _run(["git", "clone", "--no-hardlinks", str(source), str(snapshot_root)])
            _run(["git", "-C", str(snapshot_root), "checkout", "--detach", commit])
        else:
            shutil.copytree(source, snapshot_root)
        original = str(source)

    file_index = _build_file_index(snapshot_root)
    codeql_db = (
        target.codeql_db_path
        if target.codeql_db_path
        else str(run_paths["codeql_db"] / target_id)
    )

    return ScanTarget(
        target_id=target_id,
        name=target.name,
        snapshot_root=str(snapshot_root),
        original_source=original,
        commit=commit,
        language=target.language,
        scan_mode=target.scan_mode,
        codeql_db_path=codeql_db,
        pov_file=target.pov_file,
        file_index=file_index,
        exclude_paths=target.exclude_paths,
    )


def run_ingest(
    *,
    manifest_path: str,
    run_id: str,
    runs_root: str,
    detect_only: bool = True,
) -> Path:
    run_paths = ensure_run_layout(run_id, runs_root)
    events_path = run_paths["logs"] / "events.jsonl"

    append_event(events_path, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": "ingest",
        "event": "start",
        "manifest": str(Path(manifest_path).resolve()),
    })

    manifests = _load_manifest(manifest_path)
    targets: list[ScanTarget] = []
    for idx, target in enumerate(manifests, 1):
        scan_target = _sync_target(target, run_paths, idx)
        targets.append(scan_target)
        append_event(events_path, {
            "ts": datetime.now(timezone.utc).isoformat(),
            "stage": "ingest",
            "event": "target_synced",
            "target_id": scan_target.target_id,
            "snapshot_root": scan_target.snapshot_root,
            "commit": scan_target.commit,
            "indexed_files": len(scan_target.file_index),
        })

    bundle = ScanBundle(
        run_id=run_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        detect_only=detect_only,
        targets=targets,
    )

    out = run_paths["ingest"] / "scan_bundle.json"
    write_json(out, bundle.to_dict())

    append_event(events_path, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "stage": "ingest",
        "event": "complete",
        "bundle": str(out),
        "targets": len(targets),
    })

    return out
