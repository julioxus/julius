---
name: prospect
description: Local business prospecting via passive OSINT reconnaissance. Generates professional exposure reports from public data only (security headers, DNS, TLS, breach history, subdomains, technology EOL, RGPD/LSSI-CE compliance). 7-category scoring with PDF charts. Consultant info via env vars. Triggers - prospect, client outreach, local business security, exposure report.
---

# Prospect — Client Acquisition via Passive OSINT

Generate professional security exposure reports from **public data only** to prospect local businesses as security consulting clients.

## Quick Start

```
/prospect <company_name> <domain> [sector]
/prospect --batch sectors/local-hotels.csv
```

Examples:
```
/prospect "Hotel Molina Lario" hotelmolinalario.com hospitality
/prospect "Clínica Ejemplo" clinicaejemplo.com healthcare
/prospect --batch sectors/tech-companies.csv
```

## Input

1. AskUserQuestion: "¿Nombre de la empresa y dominio web?"
2. AskUserQuestion: "¿Sector? (hospitality, healthcare, legal, real-estate, fintech, tech, public-admin, other)"
3. Optional: "¿Modo batch? Proporciona un CSV con columnas: company,domain,sector"

## Workflow

### Phase 1: Passive Reconnaissance (all legal, public data)

Run all checks in parallel where possible:

**1.1 Security Headers** — `curl -sI https://{domain}` + `curl -sI http://{domain}`
- Missing: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy
- Present but misconfigured: permissive CORS, weak CSP

**1.2 TLS/SSL** — `echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null`
- Protocol version (TLS 1.2+ required), certificate expiry, issuer, SAN coverage
- Check for TLS 1.0/1.1 support: `openssl s_client -tls1 ...` / `-tls1_1 ...`

**1.3 DNS Configuration** — `dig +short {domain} ANY`, `dig +short _dmarc.{domain} TXT`, `dig +short {domain} MX`
- SPF record present and valid
- DMARC record present (p=none vs p=reject)
- DNSSEC enabled
- MX records and mail provider identification

**1.4 Subdomain Enumeration** — `curl -s "https://crt.sh/?q=%25.{domain}&output=json"` (Certificate Transparency, public)
- Count unique subdomains, identify interesting ones (admin, staging, dev, api, vpn, mail)
- No active scanning — crt.sh only

**1.5 Technology Detection** — from response headers and HTML meta
- Server header, X-Powered-By, cookies (framework fingerprinting)
- CMS detection from meta generator tag
- Known vulnerable versions if detectable

**1.6 Email Harvesting** — from website pages and common patterns
- Scrape emails from main site, /contacto, /about, /aviso-legal, /equipo
- Generate common-pattern candidates (info@, contacto@, admin@, legal@)
- All sources recorded for evidence chain

**1.7 Breach Exposure** — HIBP API (if HIBP_API_KEY in .env) or public domain check
- Check harvested emails against HaveIBeenPwned per-email API
- Fallback: domain-level breach presence check
- Report breach names and count per email, NEVER extract or store credentials

**1.8 Public Exposure** — Shodan/Censys (public search, no scanning)
- Open ports visible in Shodan: `curl -s "https://internetdb.shodan.io/{ip}"`
- Exposed services (databases, admin panels, dev tools)

**1.9 RGPD/LSSI-CE Compliance** — from homepage and common legal pages
- Cookie banner / consent mechanism detection
- Privacy policy presence (common Spanish/English paths + in-page links)
- Legal notice / aviso legal (LSSI-CE requirement for businesses)
- security.txt and robots.txt

### Phase 2: Scoring & Analysis

Score each area 1-10 (10 = secure):

| Area | Weight | What to score |
|------|--------|---------------|
| Headers | 10% | Defense-in-depth headers (low direct risk) |
| Technology | 15% | EOL software, version disclosure, CMS |
| TLS | 10% | Protocol version, certificate health |
| DNS/Email | 15% | SPF, DMARC, DNSSEC |
| Exposure | 15% | Subdomains, open ports, exposed services |
| Breach History | 15% | Email harvesting + breach presence |
| Compliance | 20% | RGPD/LSSI-CE: cookie banner, privacy policy, legal notice, security.txt |

**Overall score** = weighted average → letter grade A-F.

### Phase 3: Report Generation

Generate report using template in `reference/REPORT_TEMPLATE.md`:
- Executive summary in non-technical Spanish
- Visual score card (letter grade + areas)
- Top 3-5 findings with business impact explanation
- Comparison with sector average (if batch data available)
- Remediation roadmap (what to fix first)
- PDF via Playwright (HTML→PDF) + matplotlib for charts (radar, bar, donut gauge)

### Phase 4: Output

All outputs to `outputs/prospect-{company-slug}/`:
```
outputs/prospect-{company-slug}/
├── informe-exposicion.html          # HTML report source
├── Informe-Exposicion-{Name}.pdf   # PDF with charts
├── evidence/
│   ├── headers.txt                 # Raw curl output
│   ├── tls.txt                     # OpenSSL output
│   ├── dns.txt                     # DNS records
│   ├── subdomains.json             # crt.sh results
│   ├── shodan.json                 # InternetDB results
│   ├── emails.json                 # Harvested emails + sources
│   ├── breaches.json               # Breach check results
│   ├── tech.json                   # Technology stack + EOL detection
│   ├── tech.txt                    # Raw tech detection output
│   └── compliance.json             # RGPD/LSSI-CE compliance signals
└── scoring/
    ├── scores.json                 # Machine-readable scores
    ├── charts.png                  # Radar + horizontal bar chart
    └── gauge.png                   # Overall score donut gauge
```

## Batch Mode

For sector studies, provide CSV:
```csv
company,domain,sector
Hotel Molina Lario,hotelmolinalario.com,hospitality
```

Generates individual reports + sector summary report with anonymized comparisons.

## Critical Rules

**LEGAL**:
- **ONLY** passive reconnaissance — zero interaction beyond HTTP GET to main domain
- NO port scanning, NO vulnerability scanning, NO fuzzing, NO exploitation
- NO account creation, NO login attempts, NO authenticated access
- crt.sh and Shodan InternetDB are public data aggregators — legal to query
- Breach checks: report domain presence only, NEVER extract or store credentials

**QUALITY**:
- Reports in professional Spanish (target audience: business owners, IT managers)
- Non-technical language — explain impact in business terms, not CVE codes
- Real evidence only — every claim backed by actual command output
- Score honestly — don't inflate findings to sell services
- Include prioritized remediation recommendations

**NEVER**: Run active scanners (nmap/nuclei/ffuf) | Access authenticated areas | Store breach PII | Exaggerate severity
