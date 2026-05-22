"""
Self-contained HTML governance report generator.

Produces a single-file HTML document that PMs can open in a browser
without any server, tooling, or JavaScript framework.  All styling is
inlined; no external resources are loaded.

Usage:
  html = build_html_report(store, config)
  Path("governance_report.html").write_text(html)

Or via API:
  GET /governance/report/html
"""
from __future__ import annotations

import html as _html
from datetime import datetime
from typing import Optional

from ..detection.detector import DriftDetector
from ..engine.alerts import AlertEngine
from ..engine.rollback import RollbackEngine
from ..governance.config import GovernanceConfig
from ..governance.schema import AlertSeverity, CaseCategory, GovernanceStatus
from ..ingestion.store import DecisionStore

_CSS = """
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  margin:0;padding:24px;background:#f5f5f5;color:#333;}
.container{max-width:960px;margin:0 auto;}
h1{font-size:1.6rem;font-weight:700;margin:0 0 4px;}
.subtitle{color:#666;font-size:.9rem;margin:0 0 24px;}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;}
.card{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.1);}
.card h2{font-size:1rem;font-weight:600;margin:0 0 12px;color:#555;
  text-transform:uppercase;letter-spacing:.05em;font-size:.75rem;}
.metric{display:flex;justify-content:space-between;padding:6px 0;
  border-bottom:1px solid #f0f0f0;font-size:.9rem;}
.metric:last-child{border-bottom:none;}
.metric .label{color:#666;}
.metric .value{font-weight:600;}
.status-healthy{color:#16a34a;}
.status-drifting{color:#ca8a04;}
.status-critical{color:#dc2626;font-weight:700;}
.status-rollback{color:#fff;background:#dc2626;padding:2px 8px;border-radius:4px;}
.status-unknown{color:#6b7280;}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;
  font-weight:600;text-transform:uppercase;}
.badge-critical{background:#fee2e2;color:#dc2626;}
.badge-warning{background:#fef3c7;color:#92400e;}
.badge-info{background:#dbeafe;color:#1d4ed8;}
.drift-bar{height:8px;border-radius:4px;background:#e5e7eb;margin-top:4px;}
.drift-fill{height:100%;border-radius:4px;transition:width .3s;}
.drift-low{background:#16a34a;}
.drift-med{background:#ca8a04;}
.drift-high{background:#dc2626;}
table{width:100%;border-collapse:collapse;font-size:.88rem;}
th{text-align:left;padding:8px 12px;background:#f9fafb;border-bottom:2px solid #e5e7eb;
   font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#6b7280;}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;}
tr:last-child td{border-bottom:none;}
.full-width{grid-column:1/-1;}
.rollback-banner{background:#fee2e2;border:1px solid #fca5a5;border-radius:8px;
  padding:16px 20px;margin-bottom:24px;}
.rollback-banner h3{margin:0 0 4px;color:#991b1b;font-size:1rem;}
.rollback-banner p{margin:0;color:#7f1d1d;font-size:.875rem;}
.no-data{color:#9ca3af;font-style:italic;font-size:.875rem;}
"""

_SEV_CLASS = {
    AlertSeverity.CRITICAL: "badge-critical",
    AlertSeverity.WARNING: "badge-warning",
    AlertSeverity.INFO: "badge-info",
}


def _e(text: object) -> str:
    return _html.escape(str(text))


def _status_class(status: GovernanceStatus) -> str:
    return {
        GovernanceStatus.HEALTHY: "status-healthy",
        GovernanceStatus.DRIFTING: "status-drifting",
        GovernanceStatus.CRITICAL: "status-critical",
        GovernanceStatus.ROLLBACK_TRIGGERED: "status-rollback",
    }.get(status, "status-unknown")


def _drift_fill_class(score: float) -> str:
    if score >= 0.7:
        return "drift-high"
    if score >= 0.4:
        return "drift-med"
    return "drift-low"


def _pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def _score_label(score: float) -> str:
    if score >= 0.7:
        return "CRITICAL"
    if score >= 0.4:
        return "WARNING"
    return "OK"


def build_html_report(
    store: DecisionStore,
    config: GovernanceConfig,
    detector: Optional[DriftDetector] = None,
    alert_engine: Optional[AlertEngine] = None,
    rollback_engine: Optional[RollbackEngine] = None,
    title: str = "Agent Governance Report",
) -> str:
    """Generate a complete, self-contained HTML governance report."""
    detector = detector or DriftDetector(store, config)
    alert_engine = alert_engine or AlertEngine(store, config)
    rollback_engine = rollback_engine or RollbackEngine(store, config)

    generated_at = datetime.utcnow()
    drift_results = detector.run_detection()
    active_alerts = alert_engine.get_active_alerts()
    active_rollback = store.get_active_rollback()
    total_decisions = store.total_count()
    counts_by_cat = store.count_by_category()

    # Derive overall status
    if active_rollback:
        overall_status = GovernanceStatus.ROLLBACK_TRIGGERED
    elif any(r.drift_score >= 0.7 for r in drift_results if not r.insufficient_data and r.is_high_risk):
        overall_status = GovernanceStatus.CRITICAL
    elif any(r.drift_score >= 0.4 for r in drift_results if not r.insufficient_data):
        overall_status = GovernanceStatus.DRIFTING
    else:
        overall_status = GovernanceStatus.HEALTHY

    # ── Normal metrics ─────────────────────────────────────────────────────────
    recent = store.get_all_recent(limit=500)
    n = len(recent)
    if n:
        overall_resolution = sum(1 for d in recent if d.outcome.value == "resolved") / n
        overall_error = sum(1 for d in recent if d.outcome.value == "error") / n
        mean_pt = sum(d.processing_time_ms for d in recent) / n
    else:
        overall_resolution = overall_error = mean_pt = 0.0

    parts: list[str] = []
    a = parts.append

    a(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
<h1>{_e(title)}</h1>
<p class="subtitle">Generated {_e(generated_at.strftime('%Y-%m-%d %H:%M UTC'))} &nbsp;·&nbsp;
  Status: <span class="{_status_class(overall_status)}">{_e(overall_status.value.upper())}</span>
</p>
""")

    # Active rollback banner
    if active_rollback:
        a(f"""<div class="rollback-banner">
  <h3>🚨 Active Rollback</h3>
  <p>{_e(active_rollback.reason)}</p>
  <p style="margin-top:6px;font-size:.8rem;color:#991b1b">
    Triggered {_e(active_rollback.timestamp.strftime('%Y-%m-%d %H:%M UTC'))}
    &nbsp;by {_e(active_rollback.triggered_by)}
  </p>
</div>""")

    # ── Side-by-side: Normal metrics vs Governance signals ─────────────────────
    a("""<div class="grid">""")

    a(f"""<div class="card">
  <h2>Normal Metrics (what ops sees)</h2>
  <div class="metric"><span class="label">Total Decisions</span>
    <span class="value">{_e(total_decisions):}</span></div>
  <div class="metric"><span class="label">Overall Resolution Rate</span>
    <span class="value">{_e(_pct(overall_resolution))}</span></div>
  <div class="metric"><span class="label">Overall Error Rate</span>
    <span class="value">{_e(_pct(overall_error))}</span></div>
  <div class="metric"><span class="label">Mean Response Time</span>
    <span class="value">{mean_pt:.0f} ms</span></div>
</div>""")

    a(f"""<div class="card">
  <h2>Governance Signals (what ops misses)</h2>
  <div class="metric"><span class="label">Overall Status</span>
    <span class="value {_status_class(overall_status)}">{_e(overall_status.value.upper())}</span></div>
  <div class="metric"><span class="label">Active Alerts</span>
    <span class="value">{len(active_alerts)}</span></div>
  <div class="metric"><span class="label">Active Rollback</span>
    <span class="value">{"YES 🚨" if active_rollback else "No"}</span></div>
  <div class="metric"><span class="label">Categories Monitored</span>
    <span class="value">{len(drift_results)}</span></div>
</div>""")

    a("</div>")  # end grid

    # ── Drift scores per category ──────────────────────────────────────────────
    a("""<div class="card full-width" style="margin-bottom:16px;">
  <h2>Drift Scores by Category</h2>""")

    if not drift_results:
        a('<p class="no-data">No drift data available yet — more decisions needed.</p>')
    else:
        a("<table>")
        a("<tr><th>Category</th><th>Drift Score</th><th>Status</th>"
          "<th>Baseline N</th><th>Recent N</th>"
          "<th>Error Rate (recent)</th><th>Resolution Rate (recent)</th></tr>")
        for r in sorted(drift_results, key=lambda x: x.drift_score, reverse=True):
            if r.insufficient_data:
                a(f"""<tr>
  <td>{_e(r.category.value)}</td>
  <td colspan="6" class="no-data">{_e(r.insufficient_data_reason or "Insufficient data")}</td>
</tr>""")
                continue
            bar_width = int(r.drift_score * 100)
            fill_cls = _drift_fill_class(r.drift_score)
            label = _score_label(r.drift_score)
            sev_cls = "badge-critical" if label == "CRITICAL" else (
                "badge-warning" if label == "WARNING" else "badge-info"
            )
            baseline_n = r.baseline_stats.sample_size if r.baseline_stats else 0
            recent_n = r.recent_stats.sample_size if r.recent_stats else 0
            err_rate = _pct(r.recent_stats.error_rate) if r.recent_stats else "—"
            res_rate = _pct(r.recent_stats.resolution_rate) if r.recent_stats else "—"
            a(f"""<tr>
  <td><strong>{_e(r.category.value)}</strong>
    {"⚠️" if r.is_high_risk else ""}</td>
  <td>
    {r.drift_score:.3f}
    <div class="drift-bar"><div class="drift-fill {fill_cls}" style="width:{bar_width}%"></div></div>
  </td>
  <td><span class="badge {sev_cls}">{_e(label)}</span></td>
  <td>{baseline_n}</td><td>{recent_n}</td>
  <td>{_e(err_rate)}</td><td>{_e(res_rate)}</td>
</tr>""")
        a("</table>")
    a("</div>")

    # ── Active alerts ──────────────────────────────────────────────────────────
    a("""<div class="card full-width" style="margin-bottom:16px;">
  <h2>Active Alerts</h2>""")
    if not active_alerts:
        a('<p class="no-data">No active alerts.</p>')
    else:
        a("<table>")
        a("<tr><th>Time</th><th>Severity</th><th>Category</th><th>Message</th><th>Drift Score</th></tr>")
        for alert in active_alerts:
            sev_cls = _SEV_CLASS.get(alert.severity, "badge-info")
            a(f"""<tr>
  <td style="white-space:nowrap">{_e(alert.timestamp.strftime('%Y-%m-%d %H:%M'))}</td>
  <td><span class="badge {sev_cls}">{_e(alert.severity.value)}</span></td>
  <td>{_e(alert.category.value)}</td>
  <td>{_e(alert.message)}</td>
  <td>{alert.drift_score:.3f}</td>
</tr>""")
        a("</table>")
    a("</div>")

    # ── Decision volume by category ────────────────────────────────────────────
    a("""<div class="card full-width" style="margin-bottom:16px;">
  <h2>Decision Volume by Category</h2>""")
    if not counts_by_cat:
        a('<p class="no-data">No decisions ingested yet.</p>')
    else:
        a("<table>")
        a("<tr><th>Category</th><th>Decision Count</th><th>High Risk</th></tr>")
        for cat_str, cnt in sorted(counts_by_cat.items(), key=lambda x: -x[1]):
            try:
                is_hr = CaseCategory(cat_str).is_high_risk()
            except ValueError:
                is_hr = False
            a(f"""<tr>
  <td>{_e(cat_str)}</td>
  <td>{cnt}</td>
  <td>{"⚠️ Yes" if is_hr else "No"}</td>
</tr>""")
        a("</table>")
    a("</div>")

    a("""<p style="color:#9ca3af;font-size:.75rem;text-align:center;margin-top:16px">
  AI Agent Governance MVP &nbsp;·&nbsp; Generated by governance API
</p>
</div></body></html>""")

    return "".join(parts)
