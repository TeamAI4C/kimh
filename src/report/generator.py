"""
Vulnerability Report Generator — JSON + HTML + Graphviz.

Produces:
  - findings_report.json  (machine-readable, all findings + chains + stats)
  - findings_report.html  (self-contained dashboard with inline CSS/JS/SVG)
"""

from __future__ import annotations

import html
import json
import math
import logging
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FindingReport:
    id: str                           # "finding-001"
    rule_id: str                      # "py/insecure-protocol"
    severity: str                     # "error" | "warning" | "note"
    message: str
    status: str                       # "patched" | "attempted" | "unprocessed" | "skipped"
    selected_for_llm: bool
    llm_selection_rank: int | None
    primary_file: str
    primary_line: int
    chain: list[dict[str, Any]]       # FlowStep dicts
    rag_hits: list[dict[str, Any]]
    triage_score: int = 0


@dataclass
class ReportMetadata:
    schema_version: str = "findings_report_v1"
    language: str = ""
    timestamp: str = ""
    source_root: str = ""
    pipeline_success: bool = False
    pipeline_verdict: str = ""
    pipeline_attempts: int = 0


@dataclass
class SummaryStats:
    total_findings: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    by_rule: dict[str, int] = field(default_factory=dict)
    by_file: dict[str, int] = field(default_factory=dict)


@dataclass
class FullReport:
    metadata: ReportMetadata
    summary: SummaryStats
    findings: list[FindingReport]
    pipeline_history: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Graphviz DOT generation
# ---------------------------------------------------------------------------

_ACTION_COLORS = {
    "source": "#FFE0B2",
    "taint-source": "#FFE0B2",
    "allocate": "#C8E6C9",
    "free": "#FFCDD2",
    "unsafe-copy": "#FFCDD2",
    "use": "#EF9A9A",
    "sql-sink": "#EF9A9A",
    "code-execution": "#F48FB1",
    "intermediate": "#E0E0E0",
    "finding": "#FFF9C4",
}
_DEFAULT_COLOR = "#E0E0E0"


def _escape_dot(text: str) -> str:
    """Escape text for DOT label."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _chain_to_dot(finding_id: str, chain: list[dict[str, Any]]) -> str:
    """Convert a finding chain to a Graphviz DOT string."""
    if not chain:
        return ""
    lines = [
        f'digraph "{_escape_dot(finding_id)}" {{',
        "  rankdir=LR;",
        '  node [shape=box, style="filled,rounded", fontname="monospace", fontsize=10];',
        '  edge [color="#666666"];',
    ]
    for i, step in enumerate(chain):
        action = step.get("action", "intermediate")
        color = _ACTION_COLORS.get(action, _DEFAULT_COLOR)
        file_name = Path(step.get("file", "")).name
        line = step.get("line", "?")
        snippet = step.get("snippet", "")
        if len(snippet) > 40:
            snippet = snippet[:37] + "..."
        label = f"[{action}]\\n{file_name}:{line}\\n{_escape_dot(snippet)}"
        lines.append(f'  step_{i} [label="{label}", fillcolor="{color}"];')
    for i in range(len(chain) - 1):
        lines.append(f"  step_{i} -> step_{i+1};")
    lines.append("}")
    return "\n".join(lines)


def _dot_to_svg(dot_source: str) -> str:
    """Render DOT to SVG using graphviz library, fallback to <pre> block."""
    if not dot_source:
        return ""
    try:
        import graphviz
        src = graphviz.Source(dot_source)
        svg_bytes = src.pipe(format="svg")
        return svg_bytes.decode("utf-8")
    except Exception:
        return f"<pre class=\"dot-fallback\">{html.escape(dot_source)}</pre>"


# ---------------------------------------------------------------------------
# SVG chart generation (stdlib only)
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "error": "#E53935",
    "warning": "#FB8C00",
    "note": "#43A047",
}

_STATUS_COLORS = {
    "patched": "#43A047",
    "attempted": "#FB8C00",
    "unprocessed": "#90A4AE",
    "skipped": "#BDBDBD",
}


def _severity_pie_svg(by_severity: dict[str, int]) -> str:
    """Generate an SVG pie chart for severity distribution."""
    total = sum(by_severity.values())
    if total == 0:
        return '<svg width="200" height="200"><text x="100" y="100" text-anchor="middle">No data</text></svg>'

    cx, cy, r = 100, 100, 80
    parts: list[str] = [
        '<svg width="220" height="260" xmlns="http://www.w3.org/2000/svg">',
    ]

    if len([v for v in by_severity.values() if v > 0]) == 1:
        # Single slice — draw full circle
        for sev, count in by_severity.items():
            if count > 0:
                color = _SEVERITY_COLORS.get(sev, "#999")
                parts.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}" />')
                break
    else:
        start_angle = -math.pi / 2
        for sev in ("error", "warning", "note"):
            count = by_severity.get(sev, 0)
            if count == 0:
                continue
            sweep = 2 * math.pi * count / total
            end_angle = start_angle + sweep
            x1 = cx + r * math.cos(start_angle)
            y1 = cy + r * math.sin(start_angle)
            x2 = cx + r * math.cos(end_angle)
            y2 = cy + r * math.sin(end_angle)
            large_arc = 1 if sweep > math.pi else 0
            color = _SEVERITY_COLORS.get(sev, "#999")
            parts.append(
                f'<path d="M {cx},{cy} L {x1:.1f},{y1:.1f} '
                f'A {r},{r} 0 {large_arc} 1 {x2:.1f},{y2:.1f} Z" '
                f'fill="{color}" />'
            )
            start_angle = end_angle

    # Legend
    ly = 210
    for sev in ("error", "warning", "note"):
        count = by_severity.get(sev, 0)
        if count == 0:
            continue
        color = _SEVERITY_COLORS.get(sev, "#999")
        parts.append(f'<rect x="10" y="{ly}" width="12" height="12" fill="{color}" />')
        parts.append(
            f'<text x="28" y="{ly + 11}" font-size="11" font-family="sans-serif">'
            f'{html.escape(sev)}: {count}</text>'
        )
        ly += 16

    parts.append("</svg>")
    return "\n".join(parts)


def _rule_bar_svg(by_rule: dict[str, int]) -> str:
    """Generate an SVG horizontal bar chart for top rules."""
    if not by_rule:
        return '<svg width="400" height="40"><text x="10" y="20">No data</text></svg>'

    sorted_rules = sorted(by_rule.items(), key=lambda x: -x[1])
    if len(sorted_rules) > 15:
        top = sorted_rules[:15]
        others = sum(c for _, c in sorted_rules[15:])
        top.append(("(other)", others))
        sorted_rules = top

    max_count = max(c for _, c in sorted_rules)
    bar_h = 20
    gap = 4
    label_w = 200
    bar_max_w = 180
    total_h = len(sorted_rules) * (bar_h + gap) + 10
    total_w = label_w + bar_max_w + 40

    parts = [f'<svg width="{total_w}" height="{total_h}" xmlns="http://www.w3.org/2000/svg">']
    y = 5
    for rule, count in sorted_rules:
        w = (count / max_count) * bar_max_w if max_count > 0 else 0
        display_rule = rule if len(rule) <= 30 else rule[:27] + "..."
        parts.append(
            f'<text x="{label_w - 5}" y="{y + 14}" font-size="10" '
            f'font-family="monospace" text-anchor="end">{html.escape(display_rule)}</text>'
        )
        parts.append(
            f'<rect x="{label_w}" y="{y}" width="{w:.1f}" height="{bar_h}" '
            f'fill="#42A5F5" rx="2" />'
        )
        parts.append(
            f'<text x="{label_w + w + 4:.1f}" y="{y + 14}" font-size="10" '
            f'font-family="sans-serif">{count}</text>'
        )
        y += bar_h + gap
    parts.append("</svg>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Report building
# ---------------------------------------------------------------------------

_TEST_CI_PREFIXES = ("test/", "tests/", "test_", ".evergreen/", ".ci/", ".github/", "ci/", "spec/")

_HIGH_DANGER_SINKS = frozenset({
    "code-execution", "command-execution", "sql-sink", "xss-sink", "deserialization",
})
_MED_DANGER_SINKS = frozenset({"unsafe-copy", "file-access"})


def _compute_triage_score(finding: FindingReport) -> int:
    """Compute a 0-100 triage score from severity, sink danger, location, chain quality."""
    score = 0

    # --- Severity (40pt) ---
    sev_map = {"error": 40, "warning": 25, "note": 10}
    score += sev_map.get(finding.severity, 5)

    # --- Sink danger (30pt) ---
    actions = {step.get("action", "") for step in finding.chain}
    if actions & _HIGH_DANGER_SINKS:
        score += 30
    elif actions & _MED_DANGER_SINKS:
        score += 20
    else:
        score += 5

    # --- Code location (15pt) ---
    path_lower = finding.primary_file.lower().replace("\\", "/")
    is_test_ci = any(path_lower.startswith(p) for p in _TEST_CI_PREFIXES)
    if not is_test_ci and finding.primary_file:
        score += 15

    # --- Chain quality (15pt) ---
    has_source = any(
        step.get("action", "") in ("source", "taint-source") for step in finding.chain
    )
    has_sink = any(
        step.get("action", "") in _HIGH_DANGER_SINKS | _MED_DANGER_SINKS | {"finding"}
        for step in finding.chain
    )
    multi_step = len(finding.chain) >= 2
    if multi_step and has_source and has_sink:
        score += 15
    elif multi_step:
        score += 10
    else:
        score += 5

    return min(score, 100)


def _build_finding_reports(
    all_findings: list[dict[str, Any]],
    finding_statuses: dict[int, str],
    selected_indices: list[int],
    rag_hits: list[dict[str, Any]],
) -> list[FindingReport]:
    """Convert raw finding dicts to FindingReport objects."""
    reports: list[FindingReport] = []
    selected_set = set(selected_indices)

    for idx, f in enumerate(all_findings):
        chain = f.get("chain", [])
        primary_file = chain[0]["file"] if chain else ""
        primary_line = chain[0].get("line", 0) if chain else 0
        rank = selected_indices.index(idx) + 1 if idx in selected_set else None

        fr = FindingReport(
            id=f"finding-{idx + 1:03d}",
            rule_id=f.get("rule_id", "unknown"),
            severity=f.get("severity", "note"),
            message=f.get("message", ""),
            status=finding_statuses.get(idx, "unprocessed"),
            selected_for_llm=idx in selected_set,
            llm_selection_rank=rank,
            primary_file=primary_file,
            primary_line=primary_line,
            chain=chain,
            rag_hits=rag_hits if idx in selected_set else [],
        )
        fr.triage_score = _compute_triage_score(fr)
        reports.append(fr)
    return reports


def _build_summary(findings: list[FindingReport]) -> SummaryStats:
    """Compute summary statistics from finding reports."""
    return SummaryStats(
        total_findings=len(findings),
        by_status=dict(Counter(f.status for f in findings)),
        by_severity=dict(Counter(f.severity for f in findings)),
        by_rule=dict(Counter(f.rule_id for f in findings)),
        by_file=dict(Counter(f.primary_file for f in findings if f.primary_file)),
    )


def build_full_report(
    all_findings: list[dict[str, Any]],
    finding_statuses: dict[int, str],
    selected_indices: list[int],
    rag_hits: list[dict[str, Any]],
    profile: Any,
    pipeline_result: Any,
    inp: Any,
) -> FullReport:
    """Build the complete report data structure."""
    finding_reports = _build_finding_reports(
        all_findings, finding_statuses, selected_indices, rag_hits,
    )
    summary = _build_summary(finding_reports)
    metadata = ReportMetadata(
        language=getattr(profile, "display_name", str(profile)) if profile else "",
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_root=getattr(inp, "source_root", "") if inp else "",
        pipeline_success=getattr(pipeline_result, "success", False) if pipeline_result else False,
        pipeline_verdict=getattr(pipeline_result, "verdict", "") if pipeline_result else "",
        pipeline_attempts=getattr(pipeline_result, "attempts", 0) if pipeline_result else 0,
    )
    history = getattr(pipeline_result, "history", []) if pipeline_result else []

    return FullReport(
        metadata=metadata,
        summary=summary,
        findings=finding_reports,
        pipeline_history=history,
    )


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def _report_to_dict(report: FullReport) -> dict[str, Any]:
    """Serialize FullReport to a JSON-friendly dict."""
    return {
        "$schema": report.metadata.schema_version,
        "metadata": {
            "language": report.metadata.language,
            "timestamp": report.metadata.timestamp,
            "source_root": report.metadata.source_root,
            "pipeline_success": report.metadata.pipeline_success,
            "pipeline_verdict": report.metadata.pipeline_verdict,
            "pipeline_attempts": report.metadata.pipeline_attempts,
        },
        "summary": asdict(report.summary),
        "findings": [asdict(f) for f in report.findings],
        "pipeline_history": report.pipeline_history,
    }


def _write_json(report: FullReport, output_dir: Path) -> Path:
    """Write findings_report.json."""
    path = output_dir / "findings_report.json"
    data = _report_to_dict(report)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return path


# ---------------------------------------------------------------------------
# HTML output
# ---------------------------------------------------------------------------

_CSS = """\
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#f5f5f5;color:#333;padding:20px;max-width:1400px;margin:0 auto}
h1{font-size:1.5em;margin-bottom:4px}
.header{background:#263238;color:#fff;padding:16px 24px;border-radius:8px;margin-bottom:20px}
.header .meta{font-size:0.85em;opacity:0.8;margin-top:4px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600}
.badge-success{background:#43A047;color:#fff}
.badge-fail{background:#E53935;color:#fff}
.dashboard{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:24px}
.card{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1);
  min-width:120px;text-align:center}
.card .num{font-size:2em;font-weight:700}
.card .label{font-size:0.8em;color:#666;text-transform:uppercase}
.charts{display:flex;flex-wrap:wrap;gap:24px;margin-bottom:24px}
.chart-box{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
.chart-box h3{font-size:0.95em;margin-bottom:8px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
  overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);margin-bottom:24px}
th{background:#37474F;color:#fff;text-align:left;padding:10px 12px;font-size:0.85em;cursor:pointer}
th:hover{background:#455A64}
td{padding:8px 12px;border-bottom:1px solid #eee;font-size:0.85em}
tr:hover{background:#f0f7ff}
tr.severity-error td:first-child{border-left:3px solid #E53935}
tr.severity-warning td:first-child{border-left:3px solid #FB8C00}
tr.severity-note td:first-child{border-left:3px solid #43A047}
.status-patched{color:#43A047;font-weight:600}
.status-attempted{color:#FB8C00;font-weight:600}
.status-unprocessed{color:#90A4AE}
.status-skipped{color:#BDBDBD}
.detail-panel{display:none;background:#FAFAFA;padding:12px 16px;border-left:3px solid #42A5F5}
.detail-panel.open{display:table-row}
.detail-inner{padding:12px}
.detail-inner h4{font-size:0.9em;margin:8px 0 4px}
.detail-inner pre{background:#263238;color:#E0E0E0;padding:10px;border-radius:4px;
  overflow-x:auto;font-size:0.8em;margin:4px 0}
.dot-fallback{background:#263238;color:#E0E0E0;padding:10px;border-radius:4px;
  overflow-x:auto;font-size:0.75em;white-space:pre-wrap}
.filters{margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.filters input,.filters select{padding:6px 10px;border:1px solid #ccc;border-radius:4px;font-size:0.85em}
.history-section{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
.history-section h3{margin-bottom:8px}
.attempt-block{border-left:3px solid #42A5F5;padding:8px 12px;margin-bottom:8px;background:#FAFAFA}
.attempt-block pre{font-size:0.75em;max-height:150px;overflow:auto;background:#263238;
  color:#E0E0E0;padding:8px;border-radius:4px;margin-top:4px}
.triage-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:700;color:#fff}
.triage-high{background:#E53935}
.triage-med{background:#FB8C00}
.triage-low{background:#43A047}
.triage-minimal{background:#9E9E9E}
"""

_JS = """\
document.addEventListener('DOMContentLoaded',function(){
  // Toggle detail panel
  document.querySelectorAll('tr[data-finding-id]').forEach(function(row){
    row.style.cursor='pointer';
    row.addEventListener('click',function(){
      var detail=document.getElementById('detail-'+this.dataset.findingId);
      if(detail)detail.classList.toggle('open');
    });
  });
  // Filter
  var searchInput=document.getElementById('filter-search');
  var sevSelect=document.getElementById('filter-severity');
  var statusSelect=document.getElementById('filter-status');
  function applyFilters(){
    var q=(searchInput.value||'').toLowerCase();
    var sev=sevSelect.value;
    var st=statusSelect.value;
    document.querySelectorAll('tr[data-finding-id]').forEach(function(row){
      var show=true;
      if(q&&row.textContent.toLowerCase().indexOf(q)<0)show=false;
      if(sev&&row.dataset.severity!==sev)show=false;
      if(st&&row.dataset.status!==st)show=false;
      row.style.display=show?'':'none';
      var detail=document.getElementById('detail-'+row.dataset.findingId);
      if(detail&&!show)detail.classList.remove('open');
    });
  }
  if(searchInput)searchInput.addEventListener('input',applyFilters);
  if(sevSelect)sevSelect.addEventListener('change',applyFilters);
  if(statusSelect)statusSelect.addEventListener('change',applyFilters);
  // Sort
  document.querySelectorAll('th[data-sort]').forEach(function(th){
    th.addEventListener('click',function(){
      var col=this.dataset.sort;
      var table=this.closest('table');
      var tbody=table.querySelector('tbody');
      var rows=Array.from(tbody.querySelectorAll('tr[data-finding-id]'));
      var details=Array.from(tbody.querySelectorAll('tr.detail-panel'));
      var asc=this.dataset.asc==='1'?false:true;
      this.dataset.asc=asc?'1':'0';
      rows.sort(function(a,b){
        var va=a.querySelector('td[data-col="'+col+'"]');
        var vb=b.querySelector('td[data-col="'+col+'"]');
        va=va?va.textContent:'';vb=vb?vb.textContent:'';
        if(!isNaN(va)&&!isNaN(vb)){va=Number(va);vb=Number(vb);}
        if(va<vb)return asc?-1:1;if(va>vb)return asc?1:-1;return 0;
      });
      rows.forEach(function(row){
        tbody.appendChild(row);
        var d=document.getElementById('detail-'+row.dataset.findingId);
        if(d)tbody.appendChild(d);
      });
    });
  });
});
"""


def _html_escape(text: str) -> str:
    return html.escape(str(text))


def _render_html(report: FullReport) -> str:
    """Render the full HTML report as a self-contained string."""
    m = report.metadata
    s = report.summary

    status_badge = (
        '<span class="badge badge-success">SUCCESS</span>'
        if m.pipeline_success
        else '<span class="badge badge-fail">FAILED</span>'
    )

    # Dashboard cards
    triage_high = sum(1 for f in report.findings if f.triage_score >= 70)
    triage_med = sum(1 for f in report.findings if 50 <= f.triage_score < 70)
    cards = [
        ("Total", s.total_findings, "#42A5F5"),
        ("Triage: High", triage_high, "#E53935"),
        ("Triage: Med", triage_med, "#FB8C00"),
        ("Patched", s.by_status.get("patched", 0), "#43A047"),
        ("Attempted", s.by_status.get("attempted", 0), "#FB8C00"),
        ("Unprocessed", s.by_status.get("unprocessed", 0), "#90A4AE"),
        ("Skipped", s.by_status.get("skipped", 0), "#BDBDBD"),
    ]
    cards_html = ""
    for label, num, color in cards:
        cards_html += (
            f'<div class="card"><div class="num" style="color:{color}">{num}</div>'
            f'<div class="label">{label}</div></div>\n'
        )

    # Charts
    pie_svg = _severity_pie_svg(s.by_severity)
    bar_svg = _rule_bar_svg(s.by_rule)

    # Finding table rows + detail panels (sorted by triage score descending)
    sorted_findings = sorted(report.findings, key=lambda x: x.triage_score, reverse=True)
    table_rows = ""
    for f in sorted_findings:
        sev_class = f"severity-{f.severity}"
        status_class = f"status-{f.status}"
        if f.triage_score >= 70:
            triage_cls = "triage-high"
        elif f.triage_score >= 50:
            triage_cls = "triage-med"
        elif f.triage_score >= 30:
            triage_cls = "triage-low"
        else:
            triage_cls = "triage-minimal"
        table_rows += (
            f'<tr data-finding-id="{f.id}" data-severity="{f.severity}" data-status="{f.status}" '
            f'class="{sev_class}">'
            f'<td data-col="triage"><span class="triage-badge {triage_cls}">{f.triage_score}</span></td>'
            f'<td data-col="id">{_html_escape(f.id)}</td>'
            f'<td data-col="severity">{_html_escape(f.severity)}</td>'
            f'<td data-col="rule">{_html_escape(f.rule_id)}</td>'
            f'<td data-col="file">{_html_escape(f.primary_file)}:{f.primary_line}</td>'
            f'<td data-col="status"><span class="{status_class}">{_html_escape(f.status)}</span></td>'
            f'<td data-col="llm">{"#" + str(f.llm_selection_rank) if f.selected_for_llm else "-"}</td>'
            f'</tr>\n'
        )

        # Detail panel
        chain_dot = _chain_to_dot(f.id, f.chain)
        chain_svg = _dot_to_svg(chain_dot)

        snippets_html = ""
        for step in f.chain:
            if step.get("snippet"):
                file_name = Path(step.get("file", "")).name
                line = step.get("line", "?")
                snippets_html += (
                    f"<pre>{_html_escape(file_name)}:{line}  "
                    f"{_html_escape(step['snippet'])}</pre>"
                )

        rag_html = ""
        if f.rag_hits:
            for rh in f.rag_hits[:3]:
                meta = rh.get("metadata", {})
                cve = meta.get("cve_id", "N/A")
                vuln_type = meta.get("vuln_type", "")
                cwe_id = meta.get("cwe_id", "")
                dist = rh.get("distance", "?")
                # Distance color coding
                if isinstance(dist, (int, float)):
                    if dist < 0.5:
                        dist_color = "#43A047"  # green
                    elif dist <= 0.7:
                        dist_color = "#FB8C00"  # yellow/orange
                    else:
                        dist_color = "#E53935"  # red
                    dist_display = f'<span style="color:{dist_color}">{dist:.2f}</span>'
                    if dist > 0.7:
                        dist_display += ' <span style="color:#E53935;font-size:0.8em">[Low relevance]</span>'
                else:
                    dist_display = _html_escape(str(dist))
                meta_parts = [f"CVE: {_html_escape(str(cve))}"]
                if vuln_type:
                    meta_parts.append(f"type: {_html_escape(vuln_type)}")
                if cwe_id:
                    meta_parts.append(f"{_html_escape(cwe_id)}")
                rag_html += f'<div>{" | ".join(meta_parts)} (dist: {dist_display})</div>'

        table_rows += (
            f'<tr id="detail-{f.id}" class="detail-panel"><td colspan="7"><div class="detail-inner">'
            f'<h4>Message</h4><p>{_html_escape(f.message)}</p>'
            f'<h4>Dataflow Chain</h4>{chain_svg}'
            f'<h4>Source Snippets</h4>{snippets_html if snippets_html else "<p>No snippets</p>"}'
            f'<h4>RAG Matches</h4>{rag_html if rag_html else "<p>None</p>"}'
            f'</div></td></tr>\n'
        )

    # Pipeline history
    history_html = ""
    for h in report.pipeline_history:
        attempt = h.get("attempt", "?")
        verdict = h.get("verdict", "?")
        diff_preview = h.get("diff", "")[:500]
        history_html += (
            f'<div class="attempt-block">'
            f'<strong>Attempt {attempt}</strong> — {_html_escape(verdict)}'
            f'<pre>{_html_escape(diff_preview)}</pre></div>\n'
        )

    # Collect unique severities and statuses for filter dropdowns
    severities = sorted({f.severity for f in report.findings})
    statuses = sorted({f.status for f in report.findings})
    sev_options = '<option value="">All</option>' + "".join(
        f'<option value="{s}">{s}</option>' for s in severities
    )
    status_options = '<option value="">All</option>' + "".join(
        f'<option value="{s}">{s}</option>' for s in statuses
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FindVuln Report — {_html_escape(m.source_root)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="header">
  <h1>FindVuln Vulnerability Report {status_badge}</h1>
  <div class="meta">
    Language: {_html_escape(m.language)} &middot;
    Source: {_html_escape(m.source_root)} &middot;
    {_html_escape(m.timestamp)} &middot;
    Attempts: {m.pipeline_attempts}
  </div>
</div>

<div class="dashboard">{cards_html}</div>

<div class="charts">
  <div class="chart-box"><h3>Severity Distribution</h3>{pie_svg}</div>
  <div class="chart-box"><h3>Findings by Rule (top 15)</h3>{bar_svg}</div>
</div>

<div class="filters">
  <input id="filter-search" type="text" placeholder="Search file / rule / message…">
  <select id="filter-severity">{sev_options}</select>
  <select id="filter-status">{status_options}</select>
</div>

<table>
<thead>
<tr>
  <th data-sort="triage">Triage</th>
  <th data-sort="id">ID</th>
  <th data-sort="severity">Severity</th>
  <th data-sort="rule">Rule</th>
  <th data-sort="file">File:Line</th>
  <th data-sort="status">Status</th>
  <th data-sort="llm">LLM</th>
</tr>
</thead>
<tbody>
{table_rows}
</tbody>
</table>

<div class="history-section">
  <h3>Pipeline History</h3>
  {history_html if history_html else "<p>No attempts recorded.</p>"}
</div>

<script>{_JS}</script>
</body>
</html>"""


def _write_html(report: FullReport, output_dir: Path) -> Path:
    """Write findings_report.html."""
    path = output_dir / "findings_report.html"
    path.write_text(_render_html(report))
    return path


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_reports(
    all_findings: list[dict[str, Any]],
    finding_statuses: dict[int, str],
    selected_indices: list[int],
    rag_hits: list[dict[str, Any]],
    profile: Any,
    pipeline_result: Any,
    inp: Any,
    output_dir: str | Path,
) -> tuple[Path, Path]:
    """
    Generate findings_report.json and findings_report.html.

    Returns (json_path, html_path).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report = build_full_report(
        all_findings=all_findings,
        finding_statuses=finding_statuses,
        selected_indices=selected_indices,
        rag_hits=rag_hits,
        profile=profile,
        pipeline_result=pipeline_result,
        inp=inp,
    )

    json_path = _write_json(report, output_dir)
    html_path = _write_html(report, output_dir)

    logger.info("Reports written: %s, %s", json_path, html_path)
    return json_path, html_path
