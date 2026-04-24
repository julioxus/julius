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
    "breach": "Filtraciones",
    "compliance": "Cumplimiento Legal",
}

AREA_ICONS = {
    "headers": "&#128737;",
    "tech": "&#9881;",
    "tls": "&#128274;",
    "dns": "&#9993;",
    "exposure": "&#127760;",
    "breach": "&#128681;",
    "compliance": "&#9878;",
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

.score-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin: 16px 0; }
.score-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px; }
.score-card .area-name { font-size: 9pt; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
.score-card .area-score { font-size: 20pt; font-weight: 700; }
.score-card .area-bar { height: 6px; background: #e5e7eb; border-radius: 3px; margin-top: 6px; }
.score-card .area-bar-fill { height: 6px; border-radius: 3px; }

.badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 9pt; font-weight: 600; color: #fff; }
.sev-critical { background: #dc2626; }
.sev-high { background: #b91c1c; }
.sev-medium { background: #c2410c; }
.sev-low { background: #65a30d; }
.sev-good { background: #16a34a; }

.finding-card { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 14px 18px; margin: 12px 0; page-break-inside: avoid; }
.finding-card h3 { margin-top: 4px; }
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

    # Classify findings by severity using consistent thresholds
    # < 5 = Alta, 5-7 = Media, >= 8 = Bueno (no finding)
    high_count = sum(1 for s in scores.values() if s < 5)
    medium_count = sum(1 for s in scores.values() if 5 <= s < 8)
    finding_count = high_count + medium_count

    # Build score cards
    score_cards_html = ""
    for key, label in AREA_LABELS.items():
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

    # Technology finding (EOL software, version disclosure, CVEs) — highest impact, shown first
    tks = scores.get("tech", 5)
    eol_software = tech_data.get("eol_software", [])
    version_disclosure = tech_data.get("version_disclosure", [])
    cms_name = tech_data.get("cms", "")
    cve_findings = tech_data.get("cve_findings", [])
    plugins_detected = tech_data.get("plugins", [])
    if tks < 8 or cve_findings:
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
          {eol_html}{disclosure_html}{cms_html}{plugins_html}{cve_html}
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

    # Exposure finding
    es = scores.get("exposure", 5)
    if es < 8:
        sev, sev_label = _sev(es)
        exp_detail = escape(details.get("exposure", ""))
        exp_body = f"<p>{exp_detail}</p>" if exp_detail else ""
        findings_html += f"""
        <div class="finding-card">
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Superficie externa expuesta</h3>
          {exp_body}
          <p><span class="risk-label">Riesgo:</span> Cada servicio expuesto a Internet es un punto de entrada
          potencial. Los puertos y servicios innecesarios aumentan la superficie de ataque y pueden contener
          vulnerabilidades que permitan el acceso no autorizado a sistemas internos.</p>
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
          <h3><span class="badge sev-{sev}">{sev_label}</span> &nbsp;Carencias en cumplimiento normativo (RGPD/LSSI-CE)</h3>
          <p>La web no cumple con todos los requisitos legales obligatorios para empresas en Espa&ntilde;a.</p>
          {missing_html}
          <p><span class="risk-label">Riesgo:</span> La AEPD puede imponer multas de hasta 20 millones de euros
          o el 4% de la facturaci&oacute;n anual por incumplimiento del RGPD. La LSSI-CE exige aviso legal
          con datos de la empresa en toda web con actividad econ&oacute;mica.</p>
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
            recs_high.append("Implementar banner de cookies con consentimiento expl&iacute;cito y pol&iacute;tica de privacidad")
        elif "cookie_banner" in comp_missing:
            recs_high.append("Implementar banner de cookies con consentimiento expl&iacute;cito conforme al RGPD")
        elif "privacy_policy" in comp_missing:
            recs_high.append("Publicar pol&iacute;tica de privacidad accesible desde todas las p&aacute;ginas")
        if "legal_notice" in comp_missing:
            recs_high.append("Publicar aviso legal con datos fiscales conforme a la LSSI-CE")
        if "security_txt" in comp_missing:
            recs_medium.append("Crear archivo <code>security.txt</code> con contacto para reportes de vulnerabilidades (est&aacute;ndar RFC 9116)")

    if es < 8:
        recs_high.append("Revisar y restringir los servicios y puertos expuestos a Internet al m&iacute;nimo necesario")
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
