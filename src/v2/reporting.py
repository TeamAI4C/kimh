from __future__ import annotations

import html
from collections import Counter
import json
from pathlib import Path

from src.v2.contracts import ValidationResult
from src.v2.storage import write_json


def write_validation_reports(
    *,
    result: ValidationResult,
    output_dir: Path,
    json_name: str,
    html_name: str,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / json_name
    write_json(json_path, result.to_dict())

    rows: list[str] = []
    details: list[str] = []
    counter: Counter[str] = Counter()
    for target in result.targets:
        contribution_pretty = html.escape(json.dumps(target.model_contribution, indent=2))
        details.append(
            "<details>"
            f"<summary>Model contribution: {html.escape(target.target_id)}</summary>"
            f"<pre>{contribution_pretty}</pre>"
            "</details>"
        )
        for finding in target.final_findings:
            status = finding.final_status.value
            counter[status] += 1
            rows.append(
                "<tr>"
                f"<td>{html.escape(target.target_id)}</td>"
                f"<td>{html.escape(finding.finding_id)}</td>"
                f"<td>{html.escape(finding.rule_id)}</td>"
                f"<td>{html.escape(finding.primary_file)}:{finding.primary_line}</td>"
                f"<td>{html.escape(status)}</td>"
                f"<td>{finding.evidence_score:.2f}</td>"
                "</tr>"
            )

            finding_detail = {
                "adjudication_history": [x.to_dict() for x in finding.adjudication_history],
                "validation_evidence": [x.to_dict() for x in finding.validation_evidence],
            }
            details.append(
                "<details>"
                f"<summary>{html.escape(finding.finding_id)} details</summary>"
                f"<pre>{html.escape(json.dumps(finding_detail, indent=2))}</pre>"
                "</details>"
            )

    summary = " ".join(
        f"<span><b>{html.escape(k)}</b>: {v}</span>" for k, v in sorted(counter.items())
    ) or "<span>No findings</span>"

    html_body = f"""<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>FindVuln V2 Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; margin: 24px; }}
    .summary span {{ margin-right: 12px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f5f5f5; }}
    code {{ background: #f3f3f3; padding: 2px 4px; }}
  </style>
</head>
<body>
  <h1>FindVuln V2 Validation Report</h1>
  <p>Run ID: <code>{html.escape(result.run_id)}</code></p>
  <p>Verify runs per finding: <code>{result.verify_runs}</code></p>
  <div class=\"summary\">{summary}</div>
  <table>
    <thead>
      <tr><th>Target</th><th>Finding ID</th><th>Rule</th><th>Location</th><th>Status</th><th>Evidence Score</th></tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
  <h2>Model Contributions & Logs</h2>
  {''.join(details)}
</body>
</html>
"""

    html_path = output_dir / html_name
    html_path.write_text(html_body, encoding="utf-8")

    return json_path, html_path
