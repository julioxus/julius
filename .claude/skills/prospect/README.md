# Prospect — Client Acquisition via Passive OSINT

Generate professional security exposure reports from public data to prospect local businesses as security consulting clients.

## Quick Start

```
/prospect "Acme Corp" acmecorp.com tech
/prospect --batch sectors/local-hotels.csv
```

## Features

- **8 parallel checks**: security headers, TLS/SSL, DNS (SPF/DMARC), subdomains (crt.sh), Shodan InternetDB, technology stack (EOL detection), email harvesting + breach check (HIBP), RGPD/LSSI-CE compliance
- **7-category scoring**: Headers (10%), Technology (15%), TLS (10%), DNS (15%), Exposure (15%), Breach (15%), Compliance (20%)
- Professional PDF reports in Spanish with business-impact language
- Dual chart visualization: radar + horizontal bar chart, donut gauge for overall score
- Batch mode for sector studies (CSV input)
- Consultant info configurable via environment variables (no hardcoded PII)

## Configuration

Set these in your `.env` file to personalize reports:

```bash
PROSPECT_CONSULTANT_NAME=Your Name
PROSPECT_CONSULTANT_EMAIL=your@email.com
PROSPECT_CONSULTANT_ROLE=Security Consultant
```

If not set, reports use generic defaults.

## Legal

All reconnaissance is strictly passive — no scanning, no exploitation, no authenticated access. Only public data sources (HTTP GET, crt.sh, Shodan InternetDB, HIBP).

## Output

```
outputs/prospect-{company-slug}/
├── Informe-Exposicion-{Name}.pdf   # PDF report with charts
├── informe-exposicion.html         # HTML source
├── evidence/                       # Raw evidence (headers, tls, dns, emails, breaches, tech, compliance)
└── scoring/
    ├── scores.json                 # Machine-readable scores
    ├── charts.png                  # Radar + bar chart
    └── gauge.png                   # Overall score donut
```

## Workflow

1. Input company details (name, domain, sector)
2. Automated passive recon (8 parallel checks + sequential breach check)
3. Scoring and analysis (weighted 7-category letter grade A-F)
4. PDF report generation via Playwright (HTML → PDF)

## Dependencies

```
pip install matplotlib playwright
playwright install chromium
```

## Batch Mode

```
/prospect --batch sectors/local-hotels.csv
```

CSV format: `company,domain,sector`

Generates individual reports + anonymized sector comparison.
