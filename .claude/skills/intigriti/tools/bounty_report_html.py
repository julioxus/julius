#!/usr/bin/env python3
"""
Generates an HTML insights report from forecast data.
Usage: python3 bounty_report_html.py forecast.json -o report.html
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path


def generate_html(fc, report, researcher_name=None, recommendations=None, pending_reports=None):
    paid = report.get("paid_submissions", [])
    pending = report.get("pending_submissions", [])
    rejected = report.get("rejected_submissions", [])
    ranked = fc.get("ranked_submissions", [])
    scenarios = fc.get("scenarios", {})
    hist_rate = fc.get("historical_acceptance_rate", 0)
    confirmed = fc.get("confirmed_earnings_eur", 0)
    display_name = f" &middot; @{researcher_name}" if researcher_name else ""

    # Compute insights
    total_subs = len(paid) + len(pending) + len(rejected)
    dup_count = sum(1 for r in rejected if r["disposition"] == "duplicate")
    info_count = sum(1 for r in rejected if r["disposition"] == "informative")
    na_count = sum(1 for r in rejected if r["disposition"] in ("not_applicable", "wont_fix"))
    vdp_pending = sum(1 for r in ranked if r["program_type"] == "vdp")
    bounty_pending = sum(1 for r in ranked if r["program_type"] == "bounty")

    # Program diversity
    programs_submitted = set()
    programs_paid = set()
    for s in paid:
        programs_paid.add(s["company"])
    for s in paid + pending + rejected:
        programs_submitted.add(s["company"])

    # Severity distribution of rejections
    rejected_by_sev = {}
    for r in rejected:
        rejected_by_sev.setdefault(r["severity"], []).append(r)

    # Best EV submissions
    top5 = ranked[:5] if ranked else []

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bug Bounty Intelligence Report - {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
  :root {{
    --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a;
    --text: #e1e4ed; --muted: #8b8fa3; --accent: #6366f1;
    --green: #22c55e; --red: #ef4444; --yellow: #eab308; --blue: #3b82f6;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ font-size: 1.3rem; margin: 2rem 0 1rem; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
  h3 {{ font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }}
  .subtitle {{ color: var(--muted); margin-bottom: 2rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin: 1rem 0; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.2rem; }}
  .card-value {{ font-size: 2rem; font-weight: 700; }}
  .card-label {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; }}
  .green {{ color: var(--green); }}
  .red {{ color: var(--red); }}
  .yellow {{ color: var(--yellow); }}
  .blue {{ color: var(--blue); }}
  .accent {{ color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  th {{ color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
  tr:hover {{ background: rgba(99,102,241,0.05); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }}
  .badge-green {{ background: rgba(34,197,94,0.15); color: var(--green); }}
  .badge-red {{ background: rgba(239,68,68,0.15); color: var(--red); }}
  .badge-yellow {{ background: rgba(234,179,8,0.15); color: var(--yellow); }}
  .badge-blue {{ background: rgba(59,130,246,0.15); color: var(--blue); }}
  .badge-gray {{ background: rgba(139,143,163,0.15); color: var(--muted); }}
  .bar {{ height: 8px; border-radius: 4px; background: var(--border); overflow: hidden; margin: 0.5rem 0; }}
  .bar-fill {{ height: 100%; border-radius: 4px; }}
  .insight-box {{ background: var(--card); border-left: 3px solid var(--accent); border-radius: 0 8px 8px 0; padding: 1rem 1.2rem; margin: 1rem 0; }}
  .insight-box.warn {{ border-left-color: var(--yellow); }}
  .insight-box.good {{ border-left-color: var(--green); }}
  .insight-box.bad {{ border-left-color: var(--red); }}
  .progress-row {{ display: flex; align-items: center; gap: 0.5rem; margin: 0.3rem 0; }}
  .progress-label {{ width: 100px; font-size: 0.85rem; color: var(--muted); }}
  .progress-bar {{ flex: 1; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }}
  .progress-fill {{ height: 100%; border-radius: 3px; }}
  .scenario-table td:nth-child(2), .scenario-table td:nth-child(3) {{ text-align: right; font-family: 'SF Mono', monospace; }}
  .scenario-table th:nth-child(2), .scenario-table th:nth-child(3) {{ text-align: right; }}
  tr.expandable {{ cursor: pointer; }}
  tr.expandable:hover {{ background: rgba(99,102,241,0.08); }}
  tr.expandable td:first-child::before {{ content: '\\25B6'; display: inline-block; margin-right: 0.3rem; font-size: 0.6rem; transition: transform 0.15s; color: var(--muted); vertical-align: middle; }}
  tr.expandable.open td:first-child::before {{ transform: rotate(90deg); }}
  tr.detail-row {{ display: none; }}
  tr.detail-row.open {{ display: table-row; }}
  tr.detail-row td {{ padding: 0 0.8rem 1rem; border-bottom: 1px solid var(--border); }}
  .detail-panel {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.2rem; font-size: 0.85rem; }}
  .detail-panel .triager {{ color: var(--text); font-style: italic; margin-bottom: 0.8rem; line-height: 1.5; }}
  .detail-panel .detail-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.8rem; }}
  .detail-panel ul {{ margin: 0.3rem 0 0 1.2rem; padding: 0; }}
  .detail-panel li {{ margin: 0.2rem 0; color: var(--muted); }}
  .detail-label {{ font-weight: 600; font-size: 0.8rem; text-transform: uppercase; color: var(--muted); margin-bottom: 0.3rem; }}
  .sev-badge {{ display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; margin-left: 0.4rem; }}
  .sev-agree {{ background: rgba(34,197,94,0.15); color: var(--green); }}
  .sev-overrated {{ background: rgba(234,179,8,0.15); color: var(--yellow); }}
  .sev-underrated {{ background: rgba(59,130,246,0.15); color: var(--blue); }}
  .improvements {{ margin-top: 0.6rem; padding-top: 0.6rem; border-top: 1px solid var(--border); }}
  .meta-row {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.6rem; font-size: 0.8rem; }}
  .meta-row span {{ color: var(--muted); }}
  .meta-row strong {{ color: var(--text); }}
  .rec-action {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
  .rec-focus {{ background: rgba(34,197,94,0.15); color: var(--green); }}
  .rec-continue {{ background: rgba(59,130,246,0.15); color: var(--blue); }}
  .rec-explore {{ background: rgba(99,102,241,0.15); color: var(--accent); }}
  .rec-deprioritize {{ background: rgba(234,179,8,0.15); color: var(--yellow); }}
  .rec-abandon {{ background: rgba(239,68,68,0.15); color: var(--red); }}
  .rec-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.2rem; margin: 0.6rem 0; }}
  .rec-header {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.5rem; }}
  .rec-header h4 {{ margin: 0; font-size: 1rem; }}
  .rec-priority {{ font-size: 0.8rem; color: var(--muted); }}
  .rec-reasoning {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 0.5rem; }}
  .rec-evidence {{ display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.8rem; margin-bottom: 0.5rem; }}
  .rec-evidence span {{ color: var(--muted); }}
  .rec-next {{ font-size: 0.85rem; }}
  .rec-next li {{ margin: 0.15rem 0; }}
  .month-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.2rem; margin: 0.8rem 0; }}
  .month-card.month-current {{ border-color: var(--accent); border-width: 2px; }}
  .month-card.month-future {{ opacity: 0.7; border-style: dashed; }}
  .month-header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.8rem; }}
  .month-title {{ font-size: 1.05rem; font-weight: 600; }}
  .month-card.month-current .month-title {{ color: var(--accent); }}
  .month-card.month-future .month-title {{ color: var(--muted); }}
  .month-type-badge {{ font-size: 0.7rem; font-weight: 600; text-transform: uppercase; padding: 2px 8px; border-radius: 6px; }}
  .type-past {{ background: rgba(139,143,163,0.15); color: var(--muted); }}
  .type-current {{ background: rgba(99,102,241,0.15); color: var(--accent); }}
  .type-future {{ background: rgba(234,179,8,0.15); color: var(--yellow); }}
  .month-kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.8rem; }}
  .month-kpi {{ text-align: center; }}
  .month-kpi-value {{ font-size: 1.3rem; font-weight: 700; }}
  .month-kpi-label {{ font-size: 0.72rem; color: var(--muted); margin-top: 0.15rem; }}
  .month-bar-row {{ display: flex; align-items: center; gap: 0.5rem; margin-top: 0.7rem; }}
  .month-bar-track {{ flex: 1; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; display: flex; }}
  .month-bar-confirmed {{ height: 100%; background: var(--green); border-radius: 3px 0 0 3px; }}
  .month-bar-pending {{ height: 100%; background: rgba(99,102,241,0.5); }}
  .month-bar-labels {{ display: flex; justify-content: space-between; font-size: 0.72rem; color: var(--muted); margin-top: 0.25rem; }}
  .monthly-legend {{ display: flex; gap: 1.5rem; margin: 0.5rem 0 0.3rem; font-size: 0.78rem; color: var(--muted); }}
  .legend-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 0.3rem; vertical-align: middle; }}
  .legend-confirmed {{ background: var(--green); }}
  .legend-pending {{ background: rgba(99,102,241,0.5); }}
</style>
</head>
<body>
<div class="container">

<h1>Bug Bounty Intelligence Report</h1>
<p class="subtitle">Generated {datetime.now().strftime('%B %d, %Y at %H:%M')}{display_name}</p>

<!-- KPI Cards -->
<div class="grid">
  <div class="card">
    <div class="card-value green">&euro;{confirmed:,.0f}</div>
    <div class="card-label">Confirmed Earnings (EUR)</div>
  </div>
  <div class="card">
    <div class="card-value accent">&euro;{scenarios.get('expected',{}).get('total_eur',0):,.0f}</div>
    <div class="card-label">Expected Total (prob-weighted)</div>
  </div>
  <div class="card">
    <div class="card-value">{total_subs}</div>
    <div class="card-label">Total Submissions</div>
  </div>
  <div class="card">
    <div class="card-value {'red' if hist_rate and hist_rate < 0.3 else 'yellow' if hist_rate and hist_rate < 0.5 else 'green'}">{hist_rate:.0%}</div>
    <div class="card-label">Acceptance Rate</div>
  </div>
</div>

<!-- Funnel -->
<h2>Submission Funnel</h2>
<div class="card">
  <div class="progress-row">
    <span class="progress-label">Submitted</span>
    <div class="progress-bar"><div class="progress-fill" style="width:100%;background:var(--accent)"></div></div>
    <span>{total_subs}</span>
  </div>
  <div class="progress-row">
    <span class="progress-label">Pending</span>
    <div class="progress-bar"><div class="progress-fill" style="width:{len(pending)/max(total_subs,1)*100:.0f}%;background:var(--blue)"></div></div>
    <span>{len(pending)}</span>
  </div>
  <div class="progress-row">
    <span class="progress-label">Paid</span>
    <div class="progress-bar"><div class="progress-fill" style="width:{len(paid)/max(total_subs,1)*100:.0f}%;background:var(--green)"></div></div>
    <span>{len(paid)}</span>
  </div>
  <div class="progress-row">
    <span class="progress-label">Rejected</span>
    <div class="progress-bar"><div class="progress-fill" style="width:{len(rejected)/max(total_subs,1)*100:.0f}%;background:var(--red)"></div></div>
    <span>{len(rejected)} (dup:{dup_count} info:{info_count} na:{na_count})</span>
  </div>
</div>

<!-- Scenarios -->
<h2>Earnings Scenarios</h2>
<table class="scenario-table">
  <tr><th>Scenario</th><th>Additional</th><th>Total Career</th><th>Description</th></tr>"""

    for name, sc in scenarios.items():
        color = {"pessimistic": "red", "expected": "yellow", "optimistic": "blue", "maximum": "accent"}.get(name, "")
        html += f"""
  <tr>
    <td><span class="{color}" style="font-weight:600">{name.upper()}</span></td>
    <td>&euro;{sc['additional_eur']:,.0f}</td>
    <td><strong>&euro;{sc['total_eur']:,.0f}</strong></td>
    <td style="color:var(--muted);font-size:0.85rem">{sc['description']}</td>
  </tr>"""

    html += """
</table>"""

    # Monthly Breakdown section
    monthly = fc.get("monthly_breakdown", [])
    triage_stats = fc.get("triage_stats", {})
    if monthly:
        max_total = max((m["total_eur"] for m in monthly), default=1) or 1
        html += """

<!-- Monthly Timeline -->
<h2>Monthly Breakdown</h2>"""

        # Triage time reference
        if triage_stats and triage_stats.get("programs"):
            defaults = triage_stats.get("default_validation_days", {})
            buffer_d = triage_stats.get("pickup_buffer_days", 3)
            html += f"""
<p style="color:var(--muted);font-size:0.82rem;margin-bottom:0.6rem">
  Forecast based on program validation times (+{buffer_d}d pickup buffer).<br>"""
            inti_defaults = defaults.get("intigriti", defaults) if isinstance(defaults.get("intigriti"), dict) else defaults
            h1_defaults = defaults.get("hackerone", {})
            if inti_defaults:
                def_tags = [f'{sev} <span style="color:var(--accent)">{d+buffer_d}d</span>' for sev, d in inti_defaults.items()]
                html += f"  Intigriti defaults: {', '.join(def_tags)}"
            if h1_defaults:
                h1_tags = [f'{sev} <span style="color:#22c55e">{d+buffer_d}d</span>' for sev, d in h1_defaults.items()]
                html += f"<br>  HackerOne defaults: {', '.join(h1_tags)}"
            # Show programs with custom times
            custom_progs = [p for p, info in triage_stats["programs"].items() if info.get("source") == "program"]
            if custom_progs:
                html += f"""<br>Custom times: {', '.join(custom_progs)}"""
            html += """
</p>"""

        html += """
<div class="monthly-legend">
  <span><span class="legend-dot legend-confirmed"></span>Confirmed</span>
  <span><span class="legend-dot legend-pending"></span>Expected (pending)</span>
</div>"""
        for m in monthly:
            mtype = m["type"]
            type_label = {"past": "past", "current": "current", "future": "forecast"}.get(mtype, mtype)
            type_class = f"type-{mtype}"
            confirmed_pct = (m["confirmed_eur"] / max_total * 100) if max_total else 0
            pending_pct = (m["pending_ev_eur"] / max_total * 100) if max_total else 0

            # KPI colors
            earnings_color = "green" if m["confirmed_eur"] > 0 else "muted"
            expected_color = "accent" if m["pending_ev_eur"] > 0 else ("green" if m["confirmed_eur"] > 0 else "muted")
            subs_val = m.get("submitted", 0)
            acc_rate = m.get("acceptance_rate")
            acc_display = f"{acc_rate:.0%}" if acc_rate is not None else "&mdash;"
            acc_color = "red" if acc_rate is not None and acc_rate < 0.3 else ("yellow" if acc_rate is not None and acc_rate < 0.5 else "green")
            if acc_rate is None:
                acc_color = "muted"

            # For future months, show projected submissions as pending count
            pending_count = m.get("pending", 0)
            paid_count = m.get("paid", 0)
            rejected_count = m.get("rejected", 0)

            html += f"""
<div class="month-card month-{mtype}">
  <div class="month-header">
    <span class="month-title">{m['label']}</span>
    <span class="month-type-badge {type_class}">{type_label}</span>
  </div>
  <div class="month-kpis">
    <div class="month-kpi">
      <div class="month-kpi-value {earnings_color}">&euro;{m['confirmed_eur']:,.0f}</div>
      <div class="month-kpi-label">Confirmed</div>
    </div>
    <div class="month-kpi">
      <div class="month-kpi-value {expected_color}">&euro;{m['total_eur']:,.0f}</div>
      <div class="month-kpi-label">Expected Total</div>
    </div>
    <div class="month-kpi">
      <div class="month-kpi-value">{subs_val}</div>
      <div class="month-kpi-label">Submitted</div>
    </div>
    <div class="month-kpi">
      <div class="month-kpi-value {acc_color}">{acc_display}</div>
      <div class="month-kpi-label">Acc. Rate</div>
    </div>
  </div>
  <div class="month-bar-row">
    <div class="month-bar-track">
      <div class="month-bar-confirmed" style="width:{confirmed_pct:.1f}%"></div>
      <div class="month-bar-pending" style="width:{pending_pct:.1f}%"></div>
    </div>
  </div>
  <div class="month-bar-labels">
    <span>{paid_count} paid &middot; {rejected_count} rejected &middot; {pending_count} pending</span>
    <span>&euro;{m['total_eur']:,.0f}</span>
  </div>
</div>"""

        html += "\n"

    html += """
<!-- Ranked Pipeline -->
<h2>Pipeline Ranked by Expected Value</h2>
<p style="color:var(--muted);font-size:0.85rem;margin-bottom:0.5rem">Click any row to expand AI triager analysis</p>
<table id="pipeline-table">
  <tr><th>#</th><th>Prob</th><th>EV (&euro;)</th><th>Potential</th><th>Sev</th><th>Deadline</th><th>Program</th><th>Title</th></tr>"""

    for i, s in enumerate(ranked, 1):
        prob = s["acceptance_prob"]
        prob_class = "badge-green" if prob >= 0.5 else "badge-yellow" if prob >= 0.3 else "badge-red"
        vdp_tag = ' <span class="badge badge-gray">VDP</span>' if s["program_type"] == "vdp" else ""
        platform = s.get("platform", "intigriti")
        platform_tag = ' <span class="badge" style="background:rgba(34,197,94,0.15);color:#22c55e;font-size:0.65rem">H1</span>' if platform == "hackerone" else ' <span class="badge" style="background:rgba(99,102,241,0.15);color:#6366f1;font-size:0.65rem">INTI</span>'
        sev_class = {"High": "badge-red", "Critical": "badge-red", "Medium": "badge-yellow", "Low": "badge-blue"}.get(s["severity"], "badge-gray")
        has_ai = s.get("prob_source") == "ai"
        row_class = "expandable" if has_ai else ""
        row_id = f"row-{i}"

        title_display = s['title'][:80] + ('...' if len(s['title']) > 80 else '')

        # Deadline column
        est_date = s.get("est_resolve_date", "")
        overdue = s.get("est_overdue", False)
        if est_date:
            deadline_display = est_date
            if overdue:
                deadline_cell = f'<span class="badge badge-red" title="Overdue — request feedback">{est_date} &#x26A0;</span>'
            else:
                deadline_cell = f'<span style="font-size:0.8rem;color:var(--muted)">{est_date}</span>'
        else:
            deadline_cell = '&mdash;'

        html += f"""
  <tr class="{row_class}" data-target="{row_id}" onclick="toggleDetail(this)">
    <td>{i}</td>
    <td><span class="badge {prob_class}">{prob:.0%}</span></td>
    <td style="font-family:monospace">&euro;{s['expected_value_eur']:,.0f}</td>
    <td style="font-family:monospace">&euro;{s['expected_bounty_eur']:,.0f}</td>
    <td><span class="badge {sev_class}">{s['severity']}</span></td>
    <td style="white-space:nowrap">{deadline_cell}</td>
    <td>{s['company']}{platform_tag}{vdp_tag}</td>
    <td style="font-size:0.85rem">{title_display}</td>
  </tr>"""

        if has_ai:
            sev_assess = s.get("severity_assessment", "")
            sev_badge_class = {"agree": "sev-agree", "overrated": "sev-overrated", "underrated": "sev-underrated"}.get(sev_assess, "")
            sev_badge = f'<span class="sev-badge {sev_badge_class}">{sev_assess}</span>' if sev_assess else ""
            outcome = s.get("likely_outcome", "")
            outcome_color = {"accepted": "green", "informative": "yellow", "duplicate": "red", "out_of_scope": "red", "needs_more_info": "blue"}.get(outcome, "muted")
            confidence = s.get("ai_confidence", 0)
            strengths_li = "".join(f"<li>{st}</li>" for st in s.get("strengths", []))
            weaknesses_li = "".join(f"<li>{w}</li>" for w in s.get("weaknesses", []))
            improvements_li = "".join(f"<li>{imp}</li>" for imp in s.get("suggested_improvements", []))
            reasoning = s.get("triager_reasoning", "")
            cvss = s.get("cvss_vector", "") or ""
            created = (s.get("created_at") or "")[:10]
            status = s.get("status", "")

            html += f"""
  <tr class="detail-row" id="{row_id}">
    <td colspan="8">
      <div class="detail-panel">
        <div class="meta-row">
          <span>Status: <strong>{status}</strong></span>
          <span>Likely: <strong class="{outcome_color}">{outcome}</strong></span>
          <span>Severity: <strong>{s['severity']}</strong>{sev_badge}</span>
          <span>Confidence: <strong>{confidence:.0%}</strong></span>
          <span>Submitted: <strong>{created}</strong></span>
        </div>
        {f'<div class="meta-row"><span>CVSS: <strong style="font-family:monospace;font-size:0.75rem">{cvss}</strong></span></div>' if cvss else ''}
        <div class="triager">&ldquo;{reasoning}&rdquo;</div>
        <div class="detail-grid">
          <div>
            <div class="detail-label green">Strengths</div>
            <ul>{strengths_li}</ul>
          </div>
          <div>
            <div class="detail-label red">Weaknesses</div>
            <ul>{weaknesses_li}</ul>
          </div>
        </div>
        {f'<div class="improvements"><div class="detail-label yellow">Suggested Improvements</div><ul>{improvements_li}</ul></div>' if improvements_li else ''}
      </div>
    </td>
  </tr>"""

    html += """
</table>"""

    # Insights section
    html += """
<h2>Insights &amp; Recommendations</h2>"""

    # Insight 1: Acceptance rate
    if hist_rate and hist_rate < 0.25:
        html += f"""
<div class="insight-box bad">
  <h3>Low Acceptance Rate ({hist_rate:.0%})</h3>
  <p>Your acceptance rate is below the platform average (~35-40%). This suggests many findings land as informative or duplicate. <strong>Action:</strong> Before submitting, ask whether the finding has demonstrable E2E impact, not just a theoretical bug.</p>
</div>"""
    elif hist_rate and hist_rate < 0.4:
        html += f"""
<div class="insight-box warn">
  <h3>Acceptance Rate Needs Improvement ({hist_rate:.0%})</h3>
  <p>Close to average but room to improve. Duplicates ({dup_count}) are unavoidable, but informatives ({info_count}) can be prevented with better pre-submission validation.</p>
</div>"""

    # Insight 2: Duplicate problem
    if dup_count > 2:
        html += f"""
<div class="insight-box warn">
  <h3>Duplicates: {dup_count} of {len(rejected)} rejected</h3>
  <p>Duplicates are the highest opportunity cost in bug bounty. <strong>Action:</strong> On popular programs, prioritize speed over depth. On programs with fewer researchers, invest in complex business logic findings.</p>
</div>"""

    # Insight 3: Informatives
    if info_count > 2:
        html += f"""
<div class="insight-box bad">
  <h3>{info_count} Findings Closed as Informative</h3>
  <p>Each informative is time invested with zero return. Pattern detected: most are config disclosures without a complete exploit chain. <strong>Action:</strong> Apply the "can I cause real damage with this?" test before reporting. If the answer is "it depends", it will likely be informative.</p>
</div>"""

    # Insight 4: VDP strategy
    if vdp_pending > 0:
        html += f"""
<div class="insight-box">
  <h3>{vdp_pending} Submissions in VDP Programs (no guaranteed bounty)</h3>
  <p>VDPs can award bonuses but it is unpredictable. <strong>Action:</strong> Limit VDPs to exceptional findings that build reputation. Your time yields more in bounty programs.</p>
</div>"""

    # Insight 5: Program diversification
    html += f"""
<div class="insight-box good">
  <h3>Diversification: {len(programs_submitted)} programs, {len(programs_paid)} with payouts</h3>
  <p>Good diversification reduces duplicate risk. <strong>Action:</strong> Consolidate effort in 3-5 programs where you already have context instead of spreading thin.</p>
</div>"""

    # Insight 6: Best bet
    if top5:
        best = top5[0]
        html += f"""
<div class="insight-box good">
  <h3>Best Current Bet: {best['company']} - EV &euro;{best['expected_value_eur']:,.0f}</h3>
  <p>{best['title'][:80]}. With {best['acceptance_prob']:.0%} probability and &euro;{best['expected_bounty_eur']:,.0f} potential. This is your highest expected value submission.</p>
</div>"""

    # Strategy recommendations
    html += """
<h2>Improvement Plan</h2>
<div class="card">
<table>
  <tr><th>#</th><th>Area</th><th>Problem</th><th>Action</th></tr>
  <tr>
    <td>1</td>
    <td><span class="badge badge-red">Pre-submit</span></td>
    <td>Too many informatives</td>
    <td>Implement pre-submit checklist: E2E exploit? CIA impact? Reproducible by triager in 5 min?</td>
  </tr>
  <tr>
    <td>2</td>
    <td><span class="badge badge-yellow">Timing</span></td>
    <td>Duplicates on popular programs</td>
    <td>New/live-hacking programs: report fast. Stable programs: hunt business logic, not low-hanging fruit</td>
  </tr>
  <tr>
    <td>3</td>
    <td><span class="badge badge-blue">Focus</span></td>
    <td>Spread across too many programs</td>
    <td>80% time on 3-5 bounty programs. 20% exploring new ones</td>
  </tr>
  <tr>
    <td>4</td>
    <td><span class="badge badge-green">Quality</span></td>
    <td>Good reports but improvable</td>
    <td>Your Revolut report is the gold standard: own PoC, systemic impact demonstrated, honest caveats</td>
  </tr>
  <tr>
    <td>5</td>
    <td><span class="badge badge-yellow">VDP</span></td>
    <td>Time on no-bounty programs</td>
    <td>VDPs only for exceptional findings. For everything else, prioritize bounty programs</td>
  </tr>
</table>
</div>
"""

    # Program Recommendations section
    if recommendations:
        html += """
<h2>Program Recommendations</h2>
<p style="color:var(--muted);font-size:0.85rem;margin-bottom:0.8rem">Ranked by ROI potential based on past results, local findings, and engagement context</p>"""
        for rec in recommendations:
            action = rec.get("action", "")
            action_class = {"focus": "rec-focus", "continue": "rec-continue", "explore": "rec-explore", "deprioritize": "rec-deprioritize", "abandon": "rec-abandon"}.get(action, "")
            ev = rec.get("evidence", {})
            next_steps = rec.get("next_steps", [])
            next_li = "".join(f"<li>{ns}</li>" for ns in next_steps)
            roi = ev.get("estimated_roi", "")
            roi_color = {"high": "green", "medium": "yellow", "low": "red"}.get(roi, "muted")

            html += f"""
<div class="rec-card">
  <div class="rec-header">
    <span class="rec-priority">#{rec.get('priority', '')}</span>
    <h4>{rec.get('program', '')}</h4>
    <span class="rec-action {action_class}">{action}</span>
  </div>
  <div class="rec-reasoning">{rec.get('reasoning', '')}</div>
  <div class="rec-evidence">
    <span>Results: <strong>{ev.get('past_results', 'N/A')}</strong></span>
    <span>Unused findings: <strong>{ev.get('local_findings_unused', 0)}</strong></span>
    <span>ROI: <strong class="{roi_color}">{roi}</strong></span>
    <span>Competition: <strong>{ev.get('competition_level', 'N/A')}</strong></span>
  </div>
  <div class="rec-next">
    <div class="detail-label">Next Steps</div>
    <ul>{next_li}</ul>
  </div>
</div>"""

    # Pending Reports section (local INTI reports not yet submitted)
    pr = pending_reports or fc.get("pending_reports")
    if pr and pr.get("pending"):
        pending_list = pr["pending"]
        programs = pr.get("programs", {})

        # Group by program status
        open_reports = [p for p in pending_list if p.get("program_status") == "open"]
        suspended_reports = [p for p in pending_list if p.get("program_status") == "suspended"]
        other_reports = [p for p in pending_list if p.get("program_status") not in ("open", "suspended")]

        html += f"""
<h2>Pending Local Reports (Not Yet Submitted)</h2>
<p style="color:var(--muted);font-size:0.85rem;margin-bottom:0.8rem">
  {len(pending_list)} local reports found that have not been submitted to their respective platforms.
  Scan cross-references file titles with existing submissions on Intigriti and HackerOne.
</p>"""

        if open_reports:
            html += f"""
<h3 style="margin:1.2rem 0 0.5rem"><span class="badge badge-green">OPEN</span> Ready to Submit ({len(open_reports)})</h3>
<table>
  <tr><th>File</th><th>Severity</th><th>Program</th><th>Title</th></tr>"""
            for p in open_reports:
                sev = p.get("severity", "?")
                sev_class = {"High": "badge-red", "Critical": "badge-red", "Medium": "badge-yellow", "Low": "badge-blue"}.get(sev, "badge-gray")
                title_display = p.get("title", "")[:80]
                html += f"""
  <tr>
    <td style="font-family:monospace;font-size:0.8rem">{p.get('filename', '')}</td>
    <td><span class="badge {sev_class}">{sev}</span></td>
    <td>{p.get('program_name', p.get('program_dir', ''))}</td>
    <td style="font-size:0.85rem">{title_display}</td>
  </tr>"""
            html += """
</table>"""

        if suspended_reports:
            html += f"""
<h3 style="margin:1.2rem 0 0.5rem"><span class="badge badge-yellow">SUSPENDED</span> Waiting for Program to Reopen ({len(suspended_reports)})</h3>
<table>
  <tr><th>File</th><th>Severity</th><th>Program</th><th>Title</th></tr>"""
            for p in suspended_reports:
                sev = p.get("severity", "?")
                sev_class = {"High": "badge-red", "Critical": "badge-red", "Medium": "badge-yellow", "Low": "badge-blue"}.get(sev, "badge-gray")
                title_display = p.get("title", "")[:80]
                html += f"""
  <tr>
    <td style="font-family:monospace;font-size:0.8rem">{p.get('filename', '')}</td>
    <td><span class="badge {sev_class}">{sev}</span></td>
    <td>{p.get('program_name', p.get('program_dir', ''))}</td>
    <td style="font-size:0.85rem">{title_display}</td>
  </tr>"""
            html += """
</table>"""

        if other_reports:
            html += f"""
<h3 style="margin:1.2rem 0 0.5rem"><span class="badge badge-gray">UNKNOWN</span> Status Unresolved ({len(other_reports)})</h3>
<table>
  <tr><th>File</th><th>Severity</th><th>Program</th><th>Title</th></tr>"""
            for p in other_reports:
                sev = p.get("severity", "?")
                sev_class = {"High": "badge-red", "Critical": "badge-red", "Medium": "badge-yellow", "Low": "badge-blue"}.get(sev, "badge-gray")
                title_display = p.get("title", "")[:80]
                html += f"""
  <tr>
    <td style="font-family:monospace;font-size:0.8rem">{p.get('filename', '')}</td>
    <td><span class="badge {sev_class}">{sev}</span></td>
    <td>{p.get('program_name', p.get('program_dir', ''))}</td>
    <td style="font-size:0.85rem">{title_display}</td>
  </tr>"""
            html += """
</table>"""

    html += """

<script>
function toggleDetail(row) {
  if (!row.classList.contains('expandable')) return;
  var targetId = row.getAttribute('data-target');
  var detail = document.getElementById(targetId);
  if (!detail) return;
  var isOpen = detail.classList.contains('open');
  detail.classList.toggle('open');
  row.classList.toggle('open');
}
</script>

<p style="margin-top:3rem;color:var(--muted);font-size:0.8rem;text-align:center">
  Generated by bounty-forecast &middot; Data from Intigriti + HackerOne APIs
</p>

</div>
</body>
</html>"""

    return html


def main():
    parser = argparse.ArgumentParser(description="Generate HTML bounty report")
    parser.add_argument("forecast", help="Path to forecast JSON")
    parser.add_argument("--report", help="Path to report_latest.json (for submission lists)")
    parser.add_argument("-o", "--output", default="outputs/combined-inbox/bounty_report.html")
    parser.add_argument("--recommendations", help="Path to program_recommendations.json")
    parser.add_argument("--pending-reports", help="Path to pending_reports.json")
    parser.add_argument("--researcher", help="Researcher username for display", default=None)
    args = parser.parse_args()

    fc = json.loads(Path(args.forecast).read_text())

    report_path = args.report
    if not report_path:
        parent = Path(args.forecast).parent
        candidate = parent / "report_latest.json"
        if candidate.exists():
            report_path = str(candidate)

    report = json.loads(Path(report_path).read_text()) if report_path else {
        "paid_submissions": fc.get("ranked_submissions", []),
        "pending_submissions": [],
        "rejected_submissions": [],
    }

    recs_path = args.recommendations
    if not recs_path:
        parent = Path(args.forecast).parent
        candidate = parent / "program_recommendations.json"
        if candidate.exists():
            recs_path = str(candidate)

    recs = json.loads(Path(recs_path).read_text()) if recs_path else None

    pr_path = getattr(args, 'pending_reports', None)
    if not pr_path:
        parent = Path(args.forecast).parent
        candidate = parent / "pending_reports.json"
        if candidate.exists():
            pr_path = str(candidate)

    pr = json.loads(Path(pr_path).read_text()) if pr_path else None

    html = generate_html(fc, report, researcher_name=args.researcher, recommendations=recs, pending_reports=pr)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html)
    print(f"[+] HTML report: {out}")


if __name__ == "__main__":
    main()
