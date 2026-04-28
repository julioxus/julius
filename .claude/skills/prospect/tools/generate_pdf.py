#!/usr/bin/env python3
"""PDF report generator for prospect skill.

Renders an executive-style HTML report via Playwright, matching
the design language of the vendor-security-assessment reports.
Requires: playwright, matplotlib
"""

import json
import os
import sys
import base64
from html import escape
from pathlib import Path
from datetime import date


def _load_dotenv():
    """Load .env from repo root into os.environ (no third-party deps)."""
    env_path = Path(__file__).resolve().parents[4] / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip())


_load_dotenv()

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

AREA_LABELS = {
    "headers": "Cabeceras Web",
    "tech": "Tecnología",
    "tls": "SSL/TLS",
    "dns": "Email (SPF/DMARC)",
    "exposure": "Superficie Expuesta",
    "leakix": "Exposiciones (LeakIX)",
    "breach": "Filtraciones",
    "compliance": "Cumplimiento Legal",
    "misconfig": "Archivos Sensibles",
}

AREA_ICONS = {
    "headers": "&#128737;",
    "tech": "&#9881;",
    "tls": "&#128274;",
    "dns": "&#9993;",
    "exposure": "&#127760;",
    "leakix": "&#128065;",
    "breach": "&#128681;",
    "compliance": "&#9878;",
    "misconfig": "&#128270;",
}

GRADE_COLORS = {
    "A": "#16a34a", "B": "#2563eb", "C": "#d97706", "D": "#ea580c", "F": "#dc2626",
}
GRADE_BG = {
    "A": "#f0fdf4", "B": "#eff6ff", "C": "#fffbeb", "D": "#fff7ed", "F": "#fef2f2",
}

CSS = """
@page {
  size: A4; margin: 20mm 18mm 22mm 18mm;
  @bottom-right { content: "Page " counter(page) " / " counter(pages); font-size: 9pt; color: #94a3b8; }
}
* { box-sizing: border-box; }
body { font-family: -apple-system, "Helvetica Neue", Arial, sans-serif; color: #1a1a1a; font-size: 10.5pt; line-height: 1.55; }
h1 { color: #0f172a; border-bottom: 3px solid #2563eb; padding-bottom: 6px; margin-top: 0; }
h2 { color: #0f172a; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; margin-top: 28px; page-break-after: avoid; }
h3 { color: #1e3a8a; margin-top: 16px; margin-bottom: 6px; page-break-after: avoid; }

.cover { padding: 30px 0; border-bottom: 1px solid #cbd5e1; margin-bottom: 24px; }
.cover .label { color: #64748b; font-size: 11pt; letter-spacing: 1px; text-transform: uppercase; }
.cover h1 { font-size: 24pt; margin: 8px 0 6px 0; border: none; }
.cover .subtitle { font-size: 11pt; color: #475569; }
.cover .date { margin-top: 8px; color: #94a3b8; font-size: 9.5pt; }
.cover .confidential { margin-top: 4px; color: #dc2626; font-size: 9pt; font-weight: 600; letter-spacing: 0.5px; }

.summary-box { background: #f0f9ff; border: 1px solid #bae6fd; border-radius: 6px; padding: 14px 18px; margin: 16px 0; }
.summary-box strong { color: #0c4a6e; }

.grade-display { text-align: center; margin: 20px 0; }
.grade-circle { display: inline-block; width: 80px; height: 80px; border-radius: 50%; line-height: 80px; font-size: 36pt; font-weight: 700; color: #fff; text-align: center; }
.grade-score { font-size: 14pt; color: #475569; margin-top: 6px; }

.score-grid { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 10px; margin: 16px 0; }
.score-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px; }
.score-card .area-name { font-size: 9pt; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
.score-card .area-score { font-size: 20pt; font-weight: 700; }
.score-card .area-bar { height: 6px; background: #e5e7eb; border-radius: 3px; margin-top: 6px; }
.score-card .area-bar-fill { height: 6px; border-radius: 3px; }

.badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 9pt; font-weight: 600; color: #fff; }
.sev-critical { background: #dc2626; }
.sev-medium { background: #c2410c; }
.sev-low { background: #65a30d; }
.sev-good { background: #16a34a; }

.finding-card { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 14px 18px; margin: 12px 0; page-break-inside: avoid; }
.finding-card h3 { margin-top: 4px; }
.mini-table { width: auto; min-width: 180px; max-width: 340px; }
.finding-card ul { list-style: disc; padding-left: 18px; }
.finding-card code { background: #f1f5f9; padding: 1px 5px; border-radius: 3px; font-size: 8.5pt; }
.risk-label { font-weight: 600; color: #0f172a; }

table { border-collapse: collapse; width: 100%; margin: 14px 0; font-size: 9.5pt; }
table th, table td { border: 1px solid #cbd5e1; padding: 7px 10px; text-align: left; vertical-align: top; }
table th { background: #f1f5f9; font-weight: 600; }

.recommendation { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 14px 18px; margin: 20px 0; border-radius: 4px; page-break-inside: avoid; }
.recommendation h2 { margin-top: 0; border: none; color: #92400e; font-size: 13pt; }

.cta-box { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 16px 20px; margin: 20px 0; text-align: center; }
.cta-box h3 { color: #1e40af; margin-top: 0; }

.chart-container { text-align: center; margin: 16px 0; }
.chart-container img { max-width: 100%; }

.contact { margin-top: 30px; padding-top: 16px; border-top: 1px solid #e5e7eb; color: #64748b; font-size: 9.5pt; }
.disclaimer { margin-top: 20px; padding: 10px 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; font-size: 8.5pt; color: #94a3b8; }
"""


def _score_bar_color(s):
    if s >= 8: return "#16a34a"
    if s >= 5: return "#f59e0b"
    return "#dc2626"


def generate_charts(scores, total, output_path):
    if not HAS_MATPLOTLIB:
        return None, None
    labels = [AREA_LABELS.get(k, k) for k in scores]
    values = [scores[k] for k in scores]

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.5),
                             gridspec_kw={"width_ratios": [1, 1.2]})

    # Left: radar chart (improved styling)
    ax_radar = fig.add_subplot(1, 2, 1, polar=True)
    axes[0].set_visible(False)
    vals = values + values[:1]
    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False).tolist()
    angles += angles[:1]

    ax_radar.fill(angles, vals, color="#3b82f6", alpha=0.12)
    ax_radar.plot(angles, vals, color="#1e40af", linewidth=2.2, marker="o",
                  markersize=6, markerfacecolor="#1e40af", markeredgecolor="white",
                  markeredgewidth=1.5)
    ax_radar.set_xticks(angles[:-1])
    ax_radar.set_xticklabels(labels, size=8, color="#334155", fontweight="medium")
    ax_radar.set_ylim(0, 10)
    ax_radar.set_yticks([2, 4, 6, 8, 10])
    ax_radar.set_yticklabels(["2", "4", "6", "8", "10"], size=6, color="#94a3b8")
    ax_radar.spines["polar"].set_color("#e2e8f0")
    ax_radar.grid(color="#e2e8f0", linewidth=0.8)
    for i, (angle, val) in enumerate(zip(angles[:-1], values)):
        ax_radar.annotate(str(val), xy=(angle, val), fontsize=8,
                          fontweight="bold", color=_score_bar_color(val),
                          ha="center", va="bottom", xytext=(0, 6),
                          textcoords="offset points")

    # Right: horizontal bar chart
    ax_bar = axes[1]
    y_pos = np.arange(len(labels))
    colors = [_score_bar_color(v) for v in values]
    bars = ax_bar.barh(y_pos, values, color=colors, height=0.55, edgecolor="white",
                       linewidth=0.5)
    ax_bar.set_yticks(y_pos)
    ax_bar.set_yticklabels(labels, size=9, color="#334155")
    ax_bar.set_xlim(0, 10)
    ax_bar.set_xticks([0, 2, 4, 6, 8, 10])
    ax_bar.invert_yaxis()
    ax_bar.axvline(x=5, color="#f59e0b", linewidth=0.8, linestyle="--", alpha=0.5)
    ax_bar.axvline(x=8, color="#16a34a", linewidth=0.8, linestyle="--", alpha=0.5)
    ax_bar.spines["top"].set_visible(False)
    ax_bar.spines["right"].set_visible(False)
    ax_bar.spines["bottom"].set_color("#e2e8f0")
    ax_bar.spines["left"].set_color("#e2e8f0")
    ax_bar.tick_params(axis="x", colors="#94a3b8", labelsize=8)
    for bar, val in zip(bars, values):
        ax_bar.text(val + 0.2, bar.get_y() + bar.get_height() / 2, str(val),
                    va="center", ha="left", fontsize=9, fontweight="bold",
                    color=_score_bar_color(val))

    plt.tight_layout(pad=2)
    chart_path = output_path / "scoring" / "charts.png"
    plt.savefig(chart_path, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close()

    # Donut gauge for overall score
    fig2, ax2 = plt.subplots(figsize=(2.5, 2.5))
    pct = total / 100
    if total >= 75: ring_color = "#16a34a"
    elif total >= 60: ring_color = "#d97706"
    elif total >= 40: ring_color = "#ea580c"
    else: ring_color = "#dc2626"
    ax2.pie([pct, 1 - pct], colors=[ring_color, "#f1f5f9"],
            startangle=90, counterclock=False,
            wedgeprops={"width": 0.3, "edgecolor": "white", "linewidth": 2})
    ax2.text(0, 0, f"{total}", fontsize=28, fontweight="bold",
             ha="center", va="center", color=ring_color)
    ax2.text(0, -0.22, "/100", fontsize=10, ha="center", va="center", color="#94a3b8")
    gauge_path = output_path / "scoring" / "gauge.png"
    plt.savefig(gauge_path, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close()

    return chart_path, gauge_path


def score_color(score):
    if score >= 8: return "#16a34a"
    if score >= 5: return "#d97706"
    return "#dc2626"


def score_badge_class(score):
    if score >= 8: return "sev-good"
    if score >= 5: return "sev-medium"
    return "sev-critical"


def score_label(score):
    if score >= 8: return "Bueno"
    if score >= 5: return "Mejorable"
    return "Cr&iacute;tico"


def load_evidence_json(evidence_dir, filename):
    path = Path(evidence_dir) / filename
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, TypeError):
            pass
    return {}


def build_html(company, domain, scores_data, evidence_dir, chart_b64, gauge_b64="", consultant=None):
    if consultant is None:
        consultant = {}
    consultant_name = consultant.get("name", os.environ.get("PROSPECT_CONSULTANT_NAME", "Consultor de Ciberseguridad"))
    consultant_email = consultant.get("email", os.environ.get("PROSPECT_CONSULTANT_EMAIL", ""))
    consultant_role = consultant.get("role", os.environ.get("PROSPECT_CONSULTANT_ROLE", "Consultor de Ciberseguridad"))
    consultant_website = consultant.get("website", os.environ.get("PROSPECT_CONSULTANT_WEBSITE", ""))

    scores = scores_data["scores"]
    total = scores_data["total"]
    grade = scores_data["grade"]
    details = scores_data.get("details", {})
    sector = scores_data.get("sector", "")
    gc = GRADE_COLORS.get(grade, "#6b7280")

    email_data = load_evidence_json(evidence_dir, "emails.json")
    breach_data = load_evidence_json(evidence_dir, "breaches.json")
    tech_data = load_evidence_json(evidence_dir, "tech.json")
    compliance_data = load_evidence_json(evidence_dir, "compliance.json")
    subdomain_data = load_evidence_json(evidence_dir, "subdomains.json")
    shodan_data = load_evidence_json(evidence_dir, "shodan.json")
    leakix_data = load_evidence_json(evidence_dir, "leakix.json")
    sensitive_paths_data = load_evidence_json(evidence_dir, "sensitive_paths.json")

    # Classify findings by severity using consistent thresholds
    # < 5 = Alta, 5-7 = Media, >= 8 = Bueno (no finding)
    high_count = sum(1 for s in scores.values() if s < 5)
    medium_count = sum(1 for s in scores.values() if 5 <= s < 8)
    finding_count = high_count + medium_count

    # Build score cards
    score_cards_html = ""
    for key, label in AREA_LABELS.items():
        if key not in scores:
            continue
        s = scores.get(key, 5)
        color = score_color(s)
        pct = s * 10
        score_cards_html += f"""
        <div class="score-card">
          <div class="area-name">{AREA_ICONS.get(key, '')} {label}</div>
          <div class="area-score" style="color:{color}">{s}<span style="font-size:11pt;color:#94a3b8">/10</span></div>
          <div class="area-bar"><div class="area-bar-fill" style="width:{pct}%;background:{color}"></div></div>
        </div>"""

    # Build findings — each uses the same severity logic:
    #   score < 5 → Alta (sev-critical), 5-7 → Media (sev-medium)
    findings_html = ""

    def _sev(s):
        return ("critical", "Alta") if s < 5 else ("medium", "Media")

    # Sensitive paths findings (including git exposure) — each gets its own card
    sp_findings = sensitive_paths_data.get("findings", []) if isinstance(sensitive_paths_data, dict) else []
    sp_git_data = sensitive_paths_data.get("git_exposed", {}) if isinstance(sensitive_paths_data, dict) else {}

    lix_plugins_in_data = set()
    if isinstance(leakix_data, dict):
        for lk in leakix_data.get("leaks", []):
            lix_plugins_in_data.add(lk.get("plugin", ""))
    _plugin_to_sp = {
        "DotEnvConfigPlugin": "env_file",
        "DotDsStoreOpenPlugin": "ds_store",
        "PhpInfoHttpPlugin": "phpinfo",
        "ApacheStatusPlugin": "server_status",
        "WpUserEnumHttp": "wp_user_enum",
    }
    sp_cats_in_lix = {v for k, v in _plugin_to_sp.items() if k in lix_plugins_in_data}

    sev_map = {"critica": ("critical", "Cr&iacute;tica"), "alta": ("critical", "Alta"), "media": ("medium", "Media")}
    border_map = {"critica": "#ef4444", "alta": "#f97316", "media": "#eab308"}
    for spf in sorted(sp_findings, key=lambda x: ["critica", "alta", "media"].index(x.get("severity", "media"))):
        cat = spf.get("category", "")
        if cat in sp_cats_in_lix:
            continue
        sp_sev, sp_label = sev_map.get(spf.get("severity", "media"), ("medium", "Media"))
        sp_border = border_map.get(spf.get("severity", "media"), "#eab308")

        if cat == "git_exposed":
            justification = spf.get("justification", "")
            sp_body = f'<p>El directorio <code>.git</code> del repositorio de c&oacute;digo fuente es accesible p&uacute;blicamente en: <code>{escape(spf.get("url", ""))}</code></p>'
            if justification:
                jcolor = "#dc2626" if spf.get("severity") == "alta" else "#d97706"
                sp_body += f'<p style="color:{jcolor};font-style:italic;margin:6px 0 10px 0">{escape(justification)}</p>'
            if not sp_git_data:
                sp_git_data = spf.get("git_data", {})
            head_ref = sp_git_data.get("head_ref", "")
            if head_ref:
                sp_body += f'<p><strong>HEAD:</strong> <code>{escape(head_ref)}</code></p>'
            git_config = sp_git_data.get("config", {})
            if git_config.get("remote_url"):
                sp_body += f'<p><strong>Repositorio remoto:</strong> <code>{escape(git_config["remote_url"])}</code></p>'
            git_refs = sp_git_data.get("refs", [])
            if git_refs:
                ref_items = "".join(f"<li><code>{escape(r['ref'])}</code> ({escape(r['hash'][:8])})</li>" for r in git_refs[:10])
                sp_body += f"<p><strong>{len(git_refs)} referencias</strong> (ramas/tags):</p><ul style='margin:4px 0 10px 18px'>{ref_items}</ul>"
            git_files = sp_git_data.get("files", [])
            if git_files:
                sensitive_patterns = [".env", "config", "password", "secret", "credential", "key", "token", "database", "db", "wp-config"]
                sensitive = [f for f in git_files if any(p in f.lower() for p in sensitive_patterns)]
                file_items = "".join(f"<li><code>{escape(f)}</code></li>" for f in git_files[:30])
                sp_body += f"<p><strong>{len(git_files)} archivos</strong> del proyecto mapeados desde el &iacute;ndice Git:</p><ul style='margin:4px 0 10px 18px'>{file_items}</ul>"
                if len(git_files) > 30:
                    sp_body += f"<p style='color:#94a3b8;font-size:9pt'>… y {len(git_files) - 30} m&aacute;s</p>"
                if sensitive:
                    sens_items = "".join(f"<li><code style='color:#ef4444'>{escape(f)}</code></li>" for f in sensitive[:10])
                    sp_body += f"<p style='color:#ef4444'><strong>&#9888; Archivos potencialmente sensibles detectados:</strong></p><ul style='margin:4px 0 10px 18px'>{sens_items}</ul>"
            log_entries = sp_git_data.get("log_entries", [])
            if log_entries:
                log_rows = "".join(f"<tr><td><code>{escape(le.get('to', ''))}</code></td><td>{escape(le.get('author', ''))}</td><td>{escape(le.get('message', ''))}</td></tr>" for le in log_entries[:5])
                sp_body += f'<p><strong>Historial de commits accesible:</strong></p><table><thead><tr><th>Commit</th><th>Autor</th><th>Mensaje</th></tr></thead><tbody>{log_rows}</tbody></table>'
            if sp_git_data.get("objects_accessible"):
                sp_body += '<p style="color:#ef4444"><strong>&#9888; El directorio <code>.git/objects/</code> tambi&eacute;n es accesible</strong>, lo que permite reconstruir el c&oacute;digo fuente completo.</p>'
        else:
            sp_body = f'<p>Recurso accesible en: <code>{escape(spf.get("url", ""))}</code></p>'
            extracted = spf.get("extracted", [])
            if extracted:
                if cat == "env_file":
                    redacted = []
                    for line in extracted[:20]:
                        if "=" in line:
                            key, _, val = line.partition("=")
                            redacted.append(f"{key.strip()}={'*' * min(len(val.strip()), 8)}")
                        else:
                            redacted.append(line)
                    env_items = "".join(f"<li><code>{escape(r)}</code></li>" for r in redacted)
                    sp_body += f"<p><strong>Variables detectadas</strong> (valores redactados):</p><ul style='margin:4px 0 10px 18px'>{env_items}</ul>"
                elif cat == "wp_user_enum":
                    user_items = "".join(f"<li><code>{escape(u)}</code></li>" for u in extracted[:10])
                    sp_body += f"<p><strong>Usuarios expuestos:</strong></p><ul style='margin:4px 0 10px 18px'>{user_items}</ul>"
                elif cat == "phpinfo":
                    info_items = "".join(f"<li>{escape(i)}</li>" for i in extracted[:8])
                    sp_body += f"<p><strong>Informaci&oacute;n del servidor:</strong></p><ul style='margin:4px 0 10px 18px'>{info_items}</ul>"
                elif cat == "debug_log":
                    log_items = "".join(f"<li><code style='font-size:7.5pt'>{escape(l[:120])}</code></li>" for l in extracted[:8])
                    sp_body += f"<p><strong>Ejemplo de entradas del log:</strong></p><ul style='margin:4px 0 10px 18px'>{log_items}</ul>"
                elif cat == "server_status":
                    status_items = "".join(f"<li>{escape(s)}</li>" for s in extracted[:5])
                    sp_body += f"<p><strong>Informaci&oacute;n expuesta:</strong></p><ul style='margin:4px 0 10px 18px'>{status_items}</ul>"
                elif cat == "svn":
                    svn_items = "".join(f"<li><code>{escape(s)}</code></li>" for s in extracted[:10])
                    sp_body += f"<p><strong>Contenido del repositorio:</strong></p><ul style='margin:4px 0 10px 18px'>{svn_items}</ul>"

        sp_risk = escape(spf.get("risk", ""))
        findings_html += f"""
        <div class="finding-card" style="border-left: 4px solid {sp_border};">
          <h3><span class="badge sev-{sp_sev}">{sp_label}</span> &nbsp;{escape(spf.get("title", ""))}</h3>
          {sp_body}
          <p><span class="risk-label">Riesgo:</span> {sp_risk}</p>
        </div>"""

    # Technology finding (EOL software, version disclosure, CVEs) — highest impact, shown first
    tks = scores.get("tech", 5)
    eol_software = tech_data.get("eol_software", [])
    version_disclosure = tech_data.get("version_disclosure", [])
    cms_name = tech_data.get("cms", "")
    cve_findings = tech_data.get("cve_findings", [])
    plugins_detected = tech_data.get("plugins", [])
    nuclei_detected = tech_data.get("nuclei_detected", [])
    if tks < 8 or cve_findings or len(nuclei_detected) >= 5:
        sev, sev_label = _sev(min(tks, 7) if cve_findings else tks)
        eol_html = ""
        if eol_software:
            for eol in eol_software:
                eol_html += f"""<p><strong>{escape(eol['name'])}</strong> &mdash; fin de vida desde
                <strong>{escape(eol['eol_date'])}</strong>. No recibe parches de seguridad.
                Cualquier vulnerabilidad descubierta desde esa fecha est&aacute; presente en su servidor
                y no ser&aacute; corregida hasta que se actualice.</p>"""
        disclosure_html = ""
        if version_disclosure:
            disclosure_html = f"""<p>El servidor web muestra p&uacute;blicamente qu&eacute; programas
            y versiones utiliza. Esta informaci&oacute;n permite a un atacante buscar
            fallos de seguridad espec&iacute;ficos para esas versiones exactas, sin necesidad
            de hacer pruebas previas.</p>"""
        cms_html = ""
        if cms_name:
            cms_safe = escape(cms_name.split(" ")[0]) if " " in cms_name else escape(cms_name)
            cms_html = f"<p>La web est&aacute; construida con <strong>{escape(cms_name)}</strong>, un gestor de contenidos que requiere actualizaciones peri&oacute;dicas de seguridad.</p>"
        plugins_html = ""
        if plugins_detected:
            plugin_list = ", ".join(escape(p) for p in plugins_detected)
            plugins_html = f"""<p>Se han identificado <strong>{len(plugins_detected)}
            componentes adicionales</strong> (plugins) instalados en la web: {plugin_list}.
            Cada uno puede contener sus propios fallos de seguridad si no se mantiene actualizado.</p>"""
        nuclei_html = ""
        if nuclei_detected:
            tech_list = ", ".join(escape(t) for t in nuclei_detected[:15])
            nuclei_html = f"""<p>El an&aacute;lisis automatizado ha identificado <strong>{len(nuclei_detected)}
            tecnolog&iacute;as adicionales</strong> en uso: {tech_list}.
            Cada tecnolog&iacute;a expuesta ampl&iacute;a la superficie de ataque al revelar
            componentes espec&iacute;ficos del sistema.</p>"""
        cve_html = ""
        if cve_findings:
            total_all = sum(cf.get("cves_total", 0) for cf in cve_findings)
            total_crit = sum(cf.get("critical", 0) for cf in cve_findings)
            total_high = sum(cf.get("high", 0) for cf in cve_findings)
            severity_word = "cr&iacute;tica" if total_crit > 0 else "alta" if total_high > 0 else "moderada"
            severity_color = "#dc2626" if total_crit > 0 else "#ea580c" if total_high > 0 else "#f59e0b"
            component_lines = ""
            for cf in cve_findings:
                sw = escape(cf.get("software", ""))
                n = cf.get("cves_total", 0)
                nc = cf.get("critical", 0)
                nh = cf.get("high", 0)
                sev_tag = ""
                if nc > 0:
                    sev_tag = f" &mdash; <span style='color:#dc2626;font-weight:bold'>{nc} de gravedad cr&iacute;tica</span>"
                elif nh > 0:
                    sev_tag = f" &mdash; <span style='color:#ea580c;font-weight:bold'>{nh} de gravedad alta</span>"
                component_lines += f"<li><strong>{sw}</strong>: {n} fallos conocidos{sev_tag}</li>"
            cve_html = f"""<div style="margin:8px 0;padding:8px 12px;background:#fef2f2;border-left:3px solid {severity_color};font-size:9.5pt">
              <strong>&#9888; Se han detectado {total_all} fallos de seguridad documentados</strong>
              en los siguientes componentes del servidor:
              <ul style="margin:6px 0 4px;padding-left:20px">{component_lines}</ul>
              <p style="margin:4px 0 0">Estos fallos est&aacute;n catalogados en la base de datos
              p&uacute;blica de vulnerabilidades del gobierno de EE.UU. (NIST) y son conocidos por
              atacantes de todo el mundo. Mientras el software no se actualice, un atacante podr&iacute;a
              aprovechar estas debilidades para acceder al servidor, robar datos de clientes o
              instalar programas maliciosos.</p>
            </div>"""
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Software obsoleto y/o informaci&oacute;n t&eacute;cnica expuesta</h3>
          {eol_html}{disclosure_html}{cms_html}{plugins_html}{nuclei_html}{cve_html}
          <p><span class="risk-label">Riesgo:</span> Operar con software sin soporte de seguridad supone un
          riesgo significativo. Las vulnerabilidades listadas son p&uacute;blicamente conocidas y pueden ser
          explotadas por atacantes. En caso de brecha de datos, el uso de software obsoleto podr&iacute;a
          considerarse negligencia en el cumplimiento del RGPD (multas de hasta el 4% de la facturaci&oacute;n).</p>
        </div>"""

    # DNS/Email finding
    ds = scores.get("dns", 5)
    if ds < 8:
        sev, sev_label = _sev(ds)
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Protecci&oacute;n de email insuficiente</h3>
          <p>La configuraci&oacute;n actual de email no impide que un atacante env&iacute;e correos
          haci&eacute;ndose pasar por @{escape(domain)}.</p>
          <p><span class="risk-label">Riesgo:</span> Un atacante puede enviar facturas falsas, solicitar
          documentaci&oacute;n confidencial o pedir transferencias bancarias a nombre de la empresa,
          con emails que pasan los filtros de spam habituales.</p>
        </div>"""

    # TLS finding (Qualys-style breakdown)
    ts = scores.get("tls", 5)
    tls_data = load_evidence_json(evidence_dir, "tls.json")
    tls_grade = tls_data.get("tls_grade", "?")
    tls_total = tls_data.get("tls_score", 0)
    tls_comps = tls_data.get("tls_components", {})
    tls_protos = tls_data.get("protocols", {})
    tls_cert = tls_data.get("cert", {})
    tls_ciphers = tls_data.get("ciphers", {})
    tls_vulns = tls_data.get("vulnerabilities", [])
    tls_legacy = tls_data.get("legacy_tls", [])
    if ts < 8:
        sev, sev_label = _sev(ts)
        proto_items = ", ".join(f"{k}: {'&#10004;' if v else '&#10008;'}" for k, v in tls_protos.items()) if tls_protos else ""
        proto_html = f"<p><strong>Protocolos:</strong> {proto_items}</p>" if proto_items else ""
        legacy_html = ""
        if tls_legacy:
            legacy_html = f"<p>&#9888; Protocolos obsoletos habilitados: <strong>{', '.join(escape(l) for l in tls_legacy)}</strong>. Deben desactivarse.</p>"
        cert_html = ""
        if tls_cert.get("key_bits"):
            key_label = f"{tls_cert.get('key_type', 'RSA')} {tls_cert['key_bits']} bits"
            cert_html = f"<p><strong>Certificado:</strong> {escape(key_label)}, {escape(tls_cert.get('sig_algo', ''))}"
            if tls_cert.get("ocsp_stapling"):
                cert_html += ", OCSP stapling activo"
            cert_html += "</p>"
        cipher_html = ""
        if tls_ciphers.get("negotiated"):
            cipher_html = f"<p><strong>Cifrado negociado:</strong> {escape(tls_ciphers['negotiated'])}</p>"
        weak = tls_ciphers.get("weak", {})
        if weak:
            weak_names = ", ".join(weak.keys())
            cipher_html += f"<p>&#9888; Cifrados d&eacute;biles aceptados: <strong>{escape(weak_names)}</strong></p>"
        vuln_html = ""
        if tls_vulns:
            vuln_html = "<p><strong>Vulnerabilidades:</strong> " + ", ".join(escape(v) for v in tls_vulns) + "</p>"
        score_bar = f"""<p><strong>Puntuaci&oacute;n SSL (metodolog&iacute;a Qualys):</strong> {tls_total}/100 &mdash; Grade {escape(tls_grade)}</p>
        <table style="width:100%;font-size:9pt;margin:4px 0">
          <tr><td style="width:35%">Protocolo</td><td><div class="area-bar" style="height:10px"><div class="area-bar-fill" style="width:{tls_comps.get('protocol',0)}%;background:{score_color(tls_comps.get('protocol',0)//10)}"></div></div></td><td style="width:15%;text-align:right">{tls_comps.get('protocol',0)}/100</td></tr>
          <tr><td>Intercambio de claves</td><td><div class="area-bar" style="height:10px"><div class="area-bar-fill" style="width:{tls_comps.get('key_exchange',0)}%;background:{score_color(tls_comps.get('key_exchange',0)//10)}"></div></div></td><td style="text-align:right">{tls_comps.get('key_exchange',0)}/100</td></tr>
          <tr><td>Fortaleza del cifrado</td><td><div class="area-bar" style="height:10px"><div class="area-bar-fill" style="width:{tls_comps.get('cipher_strength',0)}%;background:{score_color(tls_comps.get('cipher_strength',0)//10)}"></div></div></td><td style="text-align:right">{tls_comps.get('cipher_strength',0)}/100</td></tr>
        </table>"""
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Configuraci&oacute;n SSL/TLS mejorable</h3>
          {score_bar}
          {proto_html}{legacy_html}{cert_html}{cipher_html}{vuln_html}
          <p><span class="risk-label">Riesgo:</span> Una configuraci&oacute;n TLS d&eacute;bil permite
          que un atacante en la misma red intercepte comunicaciones entre los clientes y el servidor,
          incluyendo datos personales, credenciales y formularios.</p>
        </div>"""

    # Exposure finding — rich detail from subdomain + Shodan evidence
    es = scores.get("exposure", 5)
    if es < 8:
        sev, sev_label = _sev(es)
        exp_sections = ""

        # Subdomains (evidence file is a plain list)
        subs = subdomain_data if isinstance(subdomain_data, list) else subdomain_data.get("subdomains", []) if isinstance(subdomain_data, dict) else []
        if subs:
            sub_items = "".join(f"<li><code>{escape(s)}</code></li>" for s in subs[:20])
            exp_sections += f"<p><strong>{len(subs)} subdominios</strong> detectados via Certificate Transparency:</p><ul style='margin:4px 0 10px 18px'>{sub_items}</ul>"
            if len(subs) > 20:
                exp_sections += f"<p style='color:#94a3b8;font-size:9pt'>… y {len(subs) - 20} m&aacute;s</p>"

        # Shodan: IP, ports, services, CVEs
        sh_ports = shodan_data.get("ports", []) if isinstance(shodan_data, dict) else []
        sh_vulns = shodan_data.get("vulns", []) if isinstance(shodan_data, dict) else []
        sh_cpes = shodan_data.get("cpes", []) if isinstance(shodan_data, dict) else []
        sh_ip = shodan_data.get("ip", "") if isinstance(shodan_data, dict) else ""
        sh_tags = shodan_data.get("tags", []) if isinstance(shodan_data, dict) else []

        if sh_ports:
            port_labels = {22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt", 8443: "HTTPS-alt", 21: "FTP", 3306: "MySQL", 5432: "PostgreSQL", 3389: "RDP", 6379: "Redis", 27017: "MongoDB"}
            port_rows = ""
            unusual = []
            for p in sorted(sh_ports):
                svc = port_labels.get(p, "—")
                is_unusual = p not in (80, 443, 8080, 8443)
                cls = ' style="color:#ef4444;font-weight:600"' if is_unusual else ""
                port_rows += f"<tr><td{cls}>{p}</td><td>{svc}</td></tr>"
                if is_unusual:
                    unusual.append(str(p))
            ip_display = f" (IP: <code>{escape(sh_ip)}</code>)" if sh_ip else ""
            exp_sections += f"""<p><strong>{len(sh_ports)} puertos abiertos</strong>{ip_display}:</p>
            <table class="mini-table"><thead><tr><th>Puerto</th><th>Servicio</th></tr></thead><tbody>{port_rows}</tbody></table>"""
            if unusual:
                exp_sections += f'<p style="color:#ef4444;font-size:9pt;margin-top:4px">&#9888; Puertos no est&aacute;ndar expuestos: {", ".join(unusual)}</p>'

        if sh_cpes:
            svc_names = []
            for cpe in sh_cpes[:6]:
                parts = cpe.split(":")
                if len(parts) >= 5:
                    svc_names.append(f"{parts[3].replace('_', ' ').title()} {parts[4]}" if parts[4] else parts[3].replace("_", " ").title())
            if svc_names:
                exp_sections += "<p><strong>Software identificado:</strong> " + ", ".join(escape(s) for s in svc_names) + "</p>"

        if sh_vulns:
            vuln_items = "".join(f"<li><code>{escape(v)}</code></li>" for v in sh_vulns[:10])
            exp_sections += f"<p><strong>{len(sh_vulns)} vulnerabilidades conocidas</strong> (CVE) asociadas a los servicios expuestos:</p><ul style='margin:4px 0 10px 18px'>{vuln_items}</ul>"
            if len(sh_vulns) > 10:
                exp_sections += f"<p style='color:#94a3b8;font-size:9pt'>… y {len(sh_vulns) - 10} m&aacute;s</p>"

        if sh_tags:
            tag_desc = {"starttls": "STARTTLS habilitado", "self-signed": "certificado autofirmado", "cloud": "infraestructura cloud", "honeypot": "posible honeypot", "vpn": "VPN detectada", "eol-os": "sistema operativo sin soporte"}
            tag_labels = [tag_desc.get(t, t) for t in sh_tags]
            exp_sections += "<p><strong>Etiquetas:</strong> " + ", ".join(escape(t) for t in tag_labels) + "</p>"

        if not exp_sections:
            exp_detail = escape(details.get("exposure", ""))
            if exp_detail:
                exp_sections = f"<p>{exp_detail}</p>"

        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Superficie externa expuesta</h3>
          {exp_sections}
          <p><span class="risk-label">Riesgo:</span> Cada servicio expuesto a Internet es un punto de entrada
          potencial. Los puertos y servicios innecesarios aumentan la superficie de ataque y pueden contener
          vulnerabilidades que permitan el acceso no autorizado a sistemas internos.</p>
        </div>"""

    # LeakIX finding — confirmed data exposures with plugin details
    lix_leaks = leakix_data.get("leaks", []) if isinstance(leakix_data, dict) else []
    lix_plugin_details = leakix_data.get("plugin_details", []) if isinstance(leakix_data, dict) else []
    lix_sev = leakix_data.get("severity_breakdown", {}) if isinstance(leakix_data, dict) else {}
    if lix_leaks:
        lix_crit = lix_sev.get("critical", 0) + lix_sev.get("high", 0)
        lix_score = 3 if lix_crit > 0 else 6
        sev, sev_label = _sev(lix_score)
        sev_items = ", ".join(f"<strong>{v}</strong> de severidad {escape(k)}" for k, v in lix_sev.items())
        sev_colors = {"critical": "#dc2626", "high": "#ea580c", "medium": "#f59e0b", "low": "#3b82f6", "info": "#94a3b8"}
        sp_has_git = any(f.get("category") == "git_exposed" for f in sp_findings)
        plugin_rows = ""
        for pd in lix_plugin_details[:12]:
            if pd.get("plugin") == "GitConfigHttpPlugin" and sp_has_git:
                continue
            sc = sev_colors.get(pd.get("severity", "info"), "#94a3b8")
            hv = " &#9888;" if pd.get("high_value") else ""
            plugin_rows += (
                f"<tr><td>{escape(pd.get('label', pd.get('plugin', '')))}{hv}</td>"
                f"<td style='color:{sc};font-weight:600'>{escape(pd.get('severity', ''))}</td>"
                f"<td>{pd.get('count', 0)}</td></tr>"
            )
        plugin_table = f"""<table class="mini-table"><thead><tr>
            <th>Exposici&oacute;n detectada</th><th>Severidad</th><th>Incidencias</th>
            </tr></thead><tbody>{plugin_rows}</tbody></table>""" if plugin_rows else ""
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Exposiciones de datos confirmadas</h3>
          <p>Motores de b&uacute;squeda especializados en seguridad han indexado
          <strong>{len(lix_leaks)} exposiciones confirmadas</strong> en la infraestructura
          del dominio: {sev_items}.</p>
          {plugin_table}
          <p><span class="risk-label">Riesgo:</span> Estas exposiciones no son te&oacute;ricas &mdash;
          han sido indexadas por motores p&uacute;blicos, lo que significa que cualquier persona puede
          acceder a la informaci&oacute;n expuesta. Seg&uacute;n el RGPD, la exposici&oacute;n no controlada
          de datos puede constituir una brecha de seguridad notificable a la AEPD en un plazo de 72 horas.</p>
        </div>"""

    # Breach / email exposure finding
    bs = scores.get("breach", 5)
    all_emails = email_data.get("emails", [])
    website_emails = [e for e, s in email_data.get("sources", {}).items() if "website" in str(s)]
    breached_emails = breach_data.get("breached_emails", [])
    breach_names = breach_data.get("breaches", [])
    breach_count = breach_data.get("breach_count", 0)

    if breached_emails:
        sev, sev_label = _sev(bs)
        breach_rows = ""
        for be in breached_emails:
            bnames = ", ".join(be.get("breaches", [])[:5])
            breach_rows += f"<tr><td>{escape(be['email'])}</td><td>{be.get('count', 0)}</td><td>{escape(bnames)}</td></tr>"
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Direcciones de email expuestas en filtraciones</h3>
          <p>Se han identificado <strong>{len(all_emails)} direcciones de email</strong> asociadas a {escape(domain)}.
          De estas, <strong>{len(breached_emails)} aparecen en filtraciones de datos conocidas</strong>.</p>
          <table>
            <thead><tr><th>Email</th><th>N&ordm;</th><th>Brechas</th></tr></thead>
            <tbody>{breach_rows}</tbody>
          </table>
          <p><span class="risk-label">Riesgo:</span> Las credenciales filtradas pueden usarse para acceder
          a sistemas internos (reutilizaci&oacute;n de contrase&ntilde;as) o realizar phishing dirigido.</p>
        </div>"""
    elif breach_count > 0:
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-medium">Media</span> &nbsp;Dominio presente en filtraciones de datos</h3>
          <p>El dominio <strong>{escape(domain)}</strong> aparece en <strong>{breach_count} filtraci&oacute;n(es)</strong>
          conocida(s): {escape(', '.join(breach_names[:5]))}.</p>
          <p><span class="risk-label">Riesgo:</span> Aunque no se han identificado cuentas concretas afectadas,
          la presencia del dominio en filtraciones indica que credenciales de la organizaci&oacute;n
          pueden estar circulando en foros y mercados clandestinos.</p>
        </div>"""
    elif all_emails and bs >= 8:
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-good">Bueno</span> &nbsp;Sin filtraciones de datos detectadas</h3>
          <p>Se analizaron {len(all_emails)} direcciones de email asociadas a {escape(domain)}.
          Ninguna aparece en filtraciones de datos conocidas.</p>
        </div>"""

    # Website email exposure finding
    if website_emails:
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-medium">Media</span> &nbsp;Direcciones de email visibles en la web</h3>
          <p>Se han encontrado <strong>{len(website_emails)} direcci&oacute;n(es) de email</strong> publicadas
          directamente en el sitio web de {escape(domain)}.</p>
          <p><span class="risk-label">Riesgo:</span> Las direcciones visibles son recopiladas por bots
          para campa&ntilde;as de spam y phishing dirigido. Sustituirlas por formularios de contacto
          reduce significativamente el volumen de correo malicioso recibido.</p>
        </div>"""

    # Compliance finding (RGPD/LSSI-CE)
    cs = scores.get("compliance", 10)
    comp_checks = compliance_data.get("checks", {})
    if cs < 8:
        sev, sev_label = _sev(cs)
        missing_items = []
        check_labels = {
            "cookie_banner": "Banner de cookies / consentimiento",
            "privacy_policy": "Pol&iacute;tica de privacidad",
            "legal_notice": "Aviso legal (LSSI-CE)",
            "security_txt": "Archivo security.txt",
        }
        for check_key, label in check_labels.items():
            status = comp_checks.get(check_key, "")
            if "No" in status:
                missing_items.append(label)
        missing_html = ""
        if missing_items:
            missing_html = "<ul>" + "".join(f"<li>{m}</li>" for m in missing_items) + "</ul>"
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Elementos de cumplimiento normativo no verificados</h3>
          <p>No se ha podido verificar la presencia de los siguientes elementos
          obligatorios en la web. Esto no significa necesariamente que no existan,
          pero s&iacute; que no son f&aacute;cilmente localizables para un visitante
          o para los organismos reguladores:</p>
          {missing_html}
          <p><span class="risk-label">Recomendaci&oacute;n:</span> Conviene asegurar que estos
          elementos est&eacute;n visibles y accesibles desde cualquier p&aacute;gina del sitio.
          La normativa espa&ntilde;ola (RGPD y LSSI-CE) exige que las webs con actividad
          econ&oacute;mica muestren aviso legal, pol&iacute;tica de privacidad y mecanismo
          de consentimiento de cookies.</p>
        </div>"""

    # Headers finding — last, lowest priority (defense-in-depth)
    hs = scores.get("headers", 5)
    if hs < 8:
        sev, sev_label = _sev(hs)
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Cabeceras de seguridad web ausentes</h3>
          <p>El servidor web no env&iacute;a las cabeceras de seguridad recomendadas
          (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
          Son medidas de defensa en profundidad: reducen el impacto de otros ataques
          pero no representan una vulnerabilidad explotable por s&iacute; solas.</p>
        </div>"""

    # Radar chart
    chart_html = ""
    if chart_b64:
        chart_html = f"""
        <div class="chart-container">
          <img src="data:image/png;base64,{chart_b64}" alt="Radar de seguridad">
        </div>"""

    # Score summary table
    score_table_rows = ""
    for key, label in AREA_LABELS.items():
        s = scores.get(key, 5)
        score_table_rows += f"""
        <tr>
          <td><strong>{label}</strong></td>
          <td style="text-align:center">{s}/10</td>
          <td style="text-align:center"><span class="badge {score_badge_class(s)}">{score_label(s)}</span></td>
        </tr>"""

    # Dynamic summary text
    summary_parts = []
    if high_count:
        summary_parts.append(f"{high_count} de severidad alta")
    if medium_count:
        summary_parts.append(f"{medium_count} de severidad media")
    summary_text = f"{finding_count} &aacute;reas de mejora identificadas"
    if summary_parts:
        summary_text += " (" + ", ".join(summary_parts) + ")"

    # Dynamic recommendations based on actual findings
    recs_high = []
    recs_medium = []

    if eol_software:
        for eol in eol_software:
            recs_high.append(f"Actualizar {escape(eol['name'])} a versi&oacute;n con soporte activo")
    if version_disclosure:
        recs_high.append("Ocultar cabeceras que revelan versi&oacute;n del software (<code>X-Powered-By</code>, <code>Server</code>)")
    if ds < 8:
        recs_high.append("Configurar DMARC a <code>p=quarantine</code> (y progresivamente <code>p=reject</code>)")
    if breached_emails:
        recs_high.append("Forzar cambio de contrase&ntilde;as en las cuentas afectadas por filtraciones")

    if cs < 8:
        comp_missing = [k for k, v in comp_checks.items() if "No" in v]
        if "cookie_banner" in comp_missing and "privacy_policy" in comp_missing:
            recs_high.append("Verificar que el banner de cookies y la pol&iacute;tica de privacidad sean visibles y accesibles")
        elif "cookie_banner" in comp_missing:
            recs_high.append("Verificar que el mecanismo de consentimiento de cookies sea visible para los visitantes")
        elif "privacy_policy" in comp_missing:
            recs_high.append("Verificar que la pol&iacute;tica de privacidad sea accesible desde todas las p&aacute;ginas")
        if "legal_notice" in comp_missing:
            recs_high.append("Verificar que el aviso legal sea f&aacute;cilmente localizable en la web")
        if "security_txt" in comp_missing:
            recs_medium.append("Crear archivo <code>security.txt</code> con contacto para reportes de vulnerabilidades (est&aacute;ndar RFC 9116)")

    if es < 8:
        recs_high.append("Revisar y restringir los servicios y puertos expuestos a Internet al m&iacute;nimo necesario")

    sp_cats = {f.get("category") for f in sp_findings}
    for lix_plug, sp_cat in _plugin_to_sp.items():
        if lix_plug in lix_plugins_in_data:
            sp_cats.add(sp_cat)
    if sp_findings or sp_cats_in_lix:
        sp_crit_cats = {f.get("category") for f in sp_findings if f.get("severity") == "critica"}
        if "git_exposed" in sp_cats:
            recs_high.append("Bloquear el acceso p&uacute;blico al directorio <code>.git</code> y rotar cualquier credencial que haya estado expuesta en el repositorio")
        if "env_file" in sp_cats:
            recs_high.append("Eliminar o bloquear el acceso al archivo <code>.env</code> y rotar todas las credenciales y claves API contenidas")
        if "svn" in sp_cats:
            recs_high.append("Bloquear el acceso p&uacute;blico al directorio <code>.svn</code> y revisar el historial en busca de credenciales")
        if "backup_files" in sp_cats:
            recs_high.append("Eliminar los archivos de backup accesibles p&uacute;blicamente y revisar su contenido en busca de credenciales expuestas")
        if "db_admin" in sp_cats:
            recs_high.append("Restringir el acceso al panel de administraci&oacute;n de base de datos (adminer/phpMyAdmin) a IPs autorizadas o eliminarlo del servidor p&uacute;blico")
        if "phpinfo" in sp_cats:
            recs_high.append("Eliminar el archivo <code>phpinfo()</code> del servidor de producci&oacute;n &mdash; expone credenciales, rutas internas y configuraci&oacute;n completa")
        if "debug_log" in sp_cats:
            recs_high.append("Eliminar o proteger el archivo <code>debug.log</code> y desactivar el log de depuraci&oacute;n en producci&oacute;n")
        if "server_status" in sp_cats:
            recs_high.append("Restringir <code>server-status</code>/<code>server-info</code> de Apache a IPs internas o desactivarlo")
        if "wp_user_enum" in sp_cats:
            recs_high.append("Desactivar la enumeraci&oacute;n de usuarios de WordPress mediante la API REST (filtro <code>rest_authentication_errors</code> o plugin de seguridad)")
        if "xmlrpc" in sp_cats:
            recs_high.append("Desactivar <code>xmlrpc.php</code> de WordPress si no se utiliza (bloquearlo en <code>.htaccess</code> o mediante plugin)")
        if "ds_store" in sp_cats:
            recs_medium.append("Eliminar el archivo <code>.DS_Store</code> y a&ntilde;adirlo a <code>.gitignore</code> y reglas del servidor")

    if breach_count > 0 and not breached_emails:
        recs_medium.append("Monitorizar las filtraciones del dominio y revisar la pol&iacute;tica de contrase&ntilde;as de la organizaci&oacute;n")
    if website_emails:
        recs_medium.append("Retirar las direcciones de email visibles en la web y sustituirlas por formularios de contacto")

    if cve_findings:
        for cf in cve_findings:
            sw = escape(cf.get("software", ""))
            n_crit = cf.get("critical", 0)
            n_total = cf.get("cves_total", 0)
            if n_crit > 0:
                recs_high.append(f"Actualizar <strong>{sw}</strong> urgentemente &mdash; {n_total} vulnerabilidades conocidas ({n_crit} cr&iacute;ticas)")
            elif n_total > 0:
                recs_medium.append(f"Actualizar <strong>{sw}</strong> &mdash; {n_total} vulnerabilidades conocidas")
    elif cms_name:
        recs_medium.append(f"Verificar y actualizar {escape(cms_name)} a la &uacute;ltima versi&oacute;n")
    if hs < 8:
        recs_medium.append("A&ntilde;adir cabeceras de seguridad web (HSTS, CSP, X-Frame-Options)")
    if ts < 8:
        recs_medium.append("Actualizar configuraci&oacute;n TLS/SSL")

    recs_html = ""
    step = 1
    if recs_high:
        recs_html += "<p><strong>Prioridad alta:</strong></p><ol>"
        for r in recs_high:
            recs_html += f"<li>{r}</li>"
            step += 1
        recs_html += "</ol>"
    if recs_medium:
        recs_html += f'<p><strong>Prioridad media:</strong></p><ol start="{step}">'
        for r in recs_medium:
            recs_html += f"<li>{r}</li>"
            step += 1
        recs_html += "</ol>"

    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Informe de Exposici&oacute;n &mdash; {escape(company)}</title>
<style>{CSS}</style></head><body>

<section class="cover">
  <div class="label">An&aacute;lisis de Seguridad Externa &middot; {escape(domain)}</div>
  <h1>Informe de Exposici&oacute;n de Seguridad</h1>
  <div class="subtitle">{escape(company)}{(' &mdash; ' + escape(sector.capitalize())) if sector else ''}</div>
  <div class="date">Fecha del informe: {date.today().strftime('%d/%m/%Y')}</div>
  <div class="confidential">CONFIDENCIAL</div>
</section>

<div class="summary-box">
  <strong>Alcance:</strong> An&aacute;lisis pasivo de la superficie p&uacute;blica de
  <strong>{escape(domain)}</strong> incluyendo tecnolog&iacute;a del servidor, certificado SSL/TLS,
  configuraci&oacute;n de email (SPF/DMARC), exposici&oacute;n en brechas de datos,
  cumplimiento normativo (RGPD/LSSI-CE) y cabeceras de seguridad.<br><br>
  <strong>Resultado:</strong> {summary_text} &rarr; puntuaci&oacute;n <strong>{total}/100 ({grade})</strong>.
</div>

<div class="grade-display">
  {'<img src="data:image/png;base64,' + gauge_b64 + '" style="max-width:140px" alt="Puntuación">' if gauge_b64 else '<div class="grade-circle" style="background:' + gc + '">' + grade + '</div>'}
  <div class="grade-score">Calificaci&oacute;n: <strong>{grade}</strong></div>
</div>

<div class="score-grid">
{score_cards_html}
</div>

{chart_html}

<h2>Hallazgos</h2>
{findings_html}

<h2>Resumen de puntuaci&oacute;n</h2>
<table>
  <thead><tr><th>&Aacute;rea</th><th>Puntuaci&oacute;n</th><th>Estado</th></tr></thead>
  <tbody>{score_table_rows}</tbody>
</table>

<div class="recommendation">
  <h2>Plan de acci&oacute;n recomendado</h2>
  {recs_html}
</div>

<div class="cta-box">
  <h3>&iquest;Interesado en mejorar la seguridad de su empresa?</h3>
  <p>Este informe cubre solo la superficie externa. Como consultor especializado, ofrezco servicios
  que cubren todo el ciclo de seguridad:</p>
  <ul style="text-align:left; margin:10px auto; max-width:480px;">
    <li><strong>Test de penetraci&oacute;n</strong> &mdash; aplicaciones web, APIs, m&oacute;vil, cloud e infraestructura</li>
    <li><strong>Consultor&iacute;a de seguridad</strong> &mdash; arquitectura segura, threat modeling, revisi&oacute;n de c&oacute;digo, DevSecOps, cumplimiento (ISO 27001, SOC 2)</li>
    <li><strong>Desarrollo seguro</strong> &mdash; herramientas de seguridad a medida, integraci&oacute;n de controles, dashboards</li>
    <li><strong>Formaci&oacute;n</strong> &mdash; coding seguro, OWASP Top 10, concienciaci&oacute;n para equipos</li>
  </ul>
  {f'<p>Consulte mi perfil profesional completo y cont&aacute;cteme a trav&eacute;s del formulario en <a href="{escape(consultant_website)}" style="color:#1e40af;font-weight:600">{escape(consultant_website.replace("https://", ""))}</a>.</p>' if consultant_website else ''}
</div>

<div class="contact">
  <strong>{escape(consultant_name)}</strong> &mdash; {escape(consultant_role)}<br>
  Email: {escape(consultant_email)}
  {f'<br>Web: <a href="{escape(consultant_website)}" style="color:#2563eb">{escape(consultant_website.replace("https://", ""))}</a>' if consultant_website else ''}
</div>

<div class="disclaimer">
  Este informe se ha elaborado exclusivamente con informaci&oacute;n de acceso p&uacute;blico.
  No se ha realizado ning&uacute;n test intrusivo ni se ha accedido a ning&uacute;n sistema protegido.
  La informaci&oacute;n se proporciona de buena fe para ayudar a mejorar la postura de seguridad
  de {escape(company)}.
</div>

</body></html>"""
    return html


def generate_pdf(company, domain, scores_path, evidence_dir, output_path):
    from playwright.sync_api import sync_playwright

    scores_data = json.loads(Path(scores_path).read_text())
    chart_path, gauge_path = generate_charts(
        scores_data["scores"], scores_data["total"], output_path
    )

    chart_b64 = ""
    if chart_path and chart_path.exists():
        chart_b64 = base64.b64encode(chart_path.read_bytes()).decode()
    gauge_b64 = ""
    if gauge_path and gauge_path.exists():
        gauge_b64 = base64.b64encode(gauge_path.read_bytes()).decode()

    html = build_html(company, domain, scores_data, evidence_dir, chart_b64, gauge_b64)

    html_path = output_path / "informe-exposicion.html"
    html_path.write_text(html)

    safe_name = company.replace(" ", "-").replace("/", "-")
    pdf_path = output_path / f"Informe-Exposicion-{safe_name}.pdf"

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.resolve().as_uri())
        page.pdf(
            path=str(pdf_path),
            format="A4",
            margin={"top": "20mm", "bottom": "22mm", "left": "18mm", "right": "18mm"},
            print_background=True,
            prefer_css_page_size=True,
        )
        browser.close()

    return str(pdf_path)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <company_name> <domain> <output_dir>")
        sys.exit(1)

    company = sys.argv[1]
    domain = sys.argv[2]
    out_dir = Path(sys.argv[3])
    scores_file = out_dir / "scoring" / "scores.json"
    evidence = out_dir / "evidence"

    if not scores_file.exists():
        print(f"Error: {scores_file} not found. Run passive_recon.py first.")
        sys.exit(1)

    pdf_path = generate_pdf(company, domain, scores_file, evidence, out_dir)
    print(f"PDF generated: {pdf_path}")
