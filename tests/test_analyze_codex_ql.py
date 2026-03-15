from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.v2 import analyze
from src.v2.analyze import _dedup_findings, _normalize_timeout_seconds, _parse_generated_queries, run_analyze
from src.lang_detect import get_profile
from src.v2.llm_cli import CLIExecutionResult
from src.v2.storage import ensure_run_layout, read_json, write_json


def _pack_finding() -> dict:
    return {
        "rule_id": "py/path-injection",
        "severity": "error",
        "message": "pack finding",
        "chain": [
            {"file": "app/main.py", "line": 10, "action": "source", "snippet": "x"},
            {"file": "app/main.py", "line": 25, "action": "file-access", "snippet": "open"},
        ],
    }


def _custom_duplicate() -> dict:
    return {
        "rule_id": "py/path-injection",
        "severity": "error",
        "message": "duplicate",
        "chain": [
            {"file": "app/main.py", "line": 10, "action": "source", "snippet": "x"},
            {"file": "app/main.py", "line": 30, "action": "file-access", "snippet": "open"},
        ],
    }


def _custom_unique() -> dict:
    return {
        "rule_id": "py/sql-injection",
        "severity": "error",
        "message": "custom finding",
        "chain": [
            {"file": "app/db.py", "line": 5, "action": "source", "snippet": "x"},
            {"file": "app/db.py", "line": 20, "action": "sql-sink", "snippet": "execute"},
        ],
    }


def test_parse_generated_queries_rejects_invalid_schema() -> None:
    with pytest.raises(ValueError):
        _parse_generated_queries('{"foo": []}', max_queries=3)



def test_normalize_timeout_seconds_disables_on_non_positive() -> None:
    assert _normalize_timeout_seconds(0, default=0) is None
    assert _normalize_timeout_seconds(-10, default=300) is None
    assert _normalize_timeout_seconds("180", default=0) == 180


def test_dedup_findings_merges_pack_and_custom() -> None:
    merged = _dedup_findings([_pack_finding(), _custom_duplicate(), _custom_unique()])
    assert len(merged) == 2



def test_run_analyze_codex_ql_pack_plus_custom(monkeypatch, tmp_path: Path) -> None:
    run_id = "analyze-codex-ql"
    runs_root = tmp_path / "runs"
    run_paths = ensure_run_layout(run_id, str(runs_root))

    target_id = "demo-target-01"
    snapshot_root = run_paths["snapshots"] / target_id
    snapshot_root.mkdir(parents=True, exist_ok=True)
    (snapshot_root / "app").mkdir(parents=True, exist_ok=True)
    (snapshot_root / "app" / "main.py").write_text("print('ok')\n", encoding="utf-8")
    (snapshot_root / "app" / "db.py").write_text("print('db')\n", encoding="utf-8")

    write_json(
        run_paths["ingest"] / "scan_bundle.json",
        {
            "run_id": run_id,
            "created_at": "2026-01-01T00:00:00+00:00",
            "detect_only": True,
            "targets": [
                {
                    "target_id": target_id,
                    "name": "demo-target",
                    "snapshot_root": str(snapshot_root),
                    "original_source": str(snapshot_root),
                    "commit": None,
                    "language": "python",
                    "scan_mode": "pack",
                    "codeql_db_path": str(run_paths["codeql_db"] / target_id),
                    "pov_file": None,
                    "file_index": ["app/main.py", "app/db.py", "tests/test_x.py"],
                    "exclude_paths": ["tests/**"],
                }
            ],
        },
    )

    class FakeParsed:
        def __init__(self, payload: dict):
            self.payload = payload

        def to_dict(self) -> dict:
            return self.payload

    class FakeCodeQLRunner:
        compile_attempts: dict[str, int] = {}

        def __init__(
            self,
            cli_path: str = "codeql",  # noqa: ARG002
            language: str = "auto",  # noqa: ARG002
            query_dir: str = "src/codeql/queries",  # noqa: ARG002
            threads: int = 4,  # noqa: ARG002
            timeout: int = 600,  # noqa: ARG002
            query_mode: str = "pack",
            build_command: str | None = None,  # noqa: ARG002
        ):
            self.query_mode = query_mode

        def analyze(self, source_root: str, db_path: str):  # noqa: ARG002
            return [_pack_finding()], get_profile("python")

        def compile_query(self, query_file: str | Path, *, cwd: str | Path | None = None):  # noqa: ARG002
            name = Path(query_file).name
            count = self.compile_attempts.get(name, 0)
            self.compile_attempts[name] = count + 1
            if name.startswith("query-01") and count == 0:
                return False, "compile error"
            return True, "ok"

        def run_query(self, db_path: str, query_file: str):  # noqa: ARG002
            return Path(query_file)

        def parse_sarif(self, sarif_path: str | Path, language: str | None = None):  # noqa: ARG002
            p = str(sarif_path)
            if "query-01" in p:
                return [FakeParsed(_custom_duplicate())]
            return [FakeParsed(_custom_unique())]

    def fake_llm_run(self, model: str, command: str, prompt: str) -> CLIExecutionResult:  # noqa: ARG001
        if "FindVuln V2 Codex QL generator" in prompt:
            payload = {
                "queries": [
                    {"name": "path-query", "purpose": "check path", "ql_code": "import python\\nfrom Expr e select e"},
                    {"name": "sql-query", "purpose": "check sql", "ql_code": "import python\\nfrom Expr e select e"},
                ]
            }
            return CLIExecutionResult(model=model, ok=True, returncode=0, stdout=json.dumps(payload), stderr="")

        if "failed to compile" in prompt:
            payload = {
                "queries": [
                    {"name": "path-query-fixed", "purpose": "fixed", "ql_code": "import python\\nfrom Expr e select e"}
                ]
            }
            return CLIExecutionResult(model=model, ok=True, returncode=0, stdout=json.dumps(payload), stderr="")

        verdict = {
            "is_vulnerable": True,
            "summary": "ok",
            "evidence_locations": [{"file": "app/main.py", "line": 10, "reason": "source to sink"}],
            "cwe_id": "CWE-22",
            "cvss_estimate": 7.5,
            "reproduction_hypothesis": "run input",
            "confidence": 0.9,
        }
        return CLIExecutionResult(model=model, ok=True, returncode=0, stdout=json.dumps(verdict), stderr="")

    monkeypatch.setattr(analyze, "CodeQLRunner", FakeCodeQLRunner)
    monkeypatch.setattr("src.v2.analyze.CLIModelExecutor.run", fake_llm_run)

    cfg = {
        "sync": {"runs_root": str(runs_root)},
        "codeql": {
            "cli_path": "codeql",
            "custom_query_dir": "src/codeql/queries",
            "threads": 1,
            "timeout_seconds": 60,
            "build_command": None,
        },
        "analysis": {
            "min_consensus_confidence": 0.6,
            "require_evidence": True,
            "max_consecutive_failures": 2,
            "model_timeout_seconds": 10,
            "prompt_template_path": "src/v2/prompts/codex_default_prompt.txt",
            "exclude_primary_path_globs": ["tests/**"],
            "codex_ql": {
                "enabled": True,
                "max_queries": 2,
                "max_retries": 1,
                "timeout_seconds": 1800,
                "prompt_template_path": "src/v2/prompts/codex_ql_query_prompt.txt",
            },
        },
    }

    out = run_analyze(
        run_id=run_id,
        runs_root=str(runs_root),
        config=cfg,
        topology="codex-single-pass",
        max_rounds=1,
        codex_cli="codex exec -",
        claude_cli="claude",
        codex_ql_enabled=True,
        ql_max_queries=2,
        ql_max_retries=1,
    )

    result = read_json(out)
    target = result["targets"][0]

    assert target["generated_queries_total"] == 2
    assert target["generated_queries_compiled"] == 2
    assert target["generated_queries_failed"] == 0
    assert Path(target["generated_query_dir"]).exists()

    # pack(1) + custom(2) with one duplicate => 2 unique raw
    assert target["findings_total_raw"] == 2
    assert target["findings_selected"] == 2

    generated_dir = Path(target["generated_query_dir"])
    assert (generated_dir / "generation_plan.json").exists()
    assert (generated_dir / "compile_results.json").exists()

    events = []
    for line in (run_paths["logs"] / "events.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    analyze_start = [e for e in events if e.get("stage") == "analyze" and e.get("event") == "start"]
    assert analyze_start
    assert analyze_start[0]["codex_ql_timeout_seconds"] == 1800
    req_complete = [e for e in events if e.get("stage") == "codex_ql" and e.get("event") == "model_request_complete"]
    assert req_complete
    assert all("elapsed_ms" in e for e in req_complete)
