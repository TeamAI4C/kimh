from __future__ import annotations

from pathlib import Path

import yaml

from src.v2 import cli


def test_e2e_runs_pipeline_in_order(monkeypatch, tmp_path: Path) -> None:
    cfg_path = tmp_path / "settings.yaml"
    cfg_path.write_text(yaml.safe_dump({"sync": {"runs_root": str(tmp_path / "runs")}}), encoding="utf-8")

    calls: list[tuple[str, dict]] = []

    def fake_ingest(**kwargs):
        calls.append(("ingest", kwargs))
        return Path("/tmp/scan_bundle.json")

    def fake_analyze(**kwargs):
        calls.append(("analyze", kwargs))
        return Path("/tmp/analyze_result.json")

    def fake_validate_multishot(**kwargs):
        calls.append(("validate", kwargs))
        return "/tmp/final_report.json", "/tmp/final_report.html"

    def fake_poc(**kwargs):
        calls.append(("poc", kwargs))
        return "/tmp/poc_reports_index.json", 0

    monkeypatch.setattr(cli, "run_ingest", fake_ingest)
    monkeypatch.setattr(cli, "run_analyze", fake_analyze)
    monkeypatch.setattr(cli, "run_validate_multishot", fake_validate_multishot)
    monkeypatch.setattr(cli, "generate_poc_markdown_reports", fake_poc)

    monkeypatch.setattr(
        "sys.argv",
        [
            "findvuln",
            "--config",
            str(cfg_path),
            "e2e",
            "--manifest",
            "/tmp/manifest.yaml",
            "--run-id",
            "demo-run",
            "--execution-owner",
            "codex-host",
        ],
    )

    cli.main()

    assert [x[0] for x in calls] == ["ingest", "analyze", "validate", "poc"]
    assert calls[0][1]["run_id"] == "demo-run"
    assert calls[1][1]["run_id"] == "demo-run"
    assert calls[1][1]["codex_ql_enabled"] is True
    assert calls[1][1]["ql_max_queries"] == 6
    assert calls[1][1]["ql_max_retries"] == 2
    assert calls[2][1]["run_id"] == "demo-run"
    assert calls[2][1]["execution_owner"] == "codex-host"
    assert calls[3][1]["run_id"] == "demo-run"
