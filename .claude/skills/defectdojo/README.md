---
name: defectdojo
description: DefectDojo vulnerability management - import pentest findings, manage products/engagements, sync evidence via API v2.
---

# DefectDojo Skill

Import validated security findings into DefectDojo for vulnerability lifecycle management.

## Quick Start

```bash
# Set credentials
export DEFECTDOJO_URL=https://defectdojo.example.com
export DEFECTDOJO_TOKEN=<your_api_key>

# Invoke skill
/defectdojo "Product Name" "Engagement Name"
```

## Features

- API v2 authentication and validation
- Product and engagement creation/management
- Finding import with CWE mapping and CVSS scoring
- Evidence file upload (PoCs, screenshots, HTTP logs)
- Scanner output import (Nuclei, Nmap, ZAP, Burp, Trivy, 150+ formats)
- Deduplication against existing findings
- Import verification and summary reporting

## Structure

```
.claude/skills/defectdojo/
├── SKILL.md              # Skill definition and workflows
├── README.md             # This file
├── reference/
│   ├── API_REFERENCE.md  # DefectDojo API v2 endpoints
│   └── CWE_MAPPING.md   # Vulnerability → CWE ID mapping
├── tools/
│   ├── finding_importer.py   # Import findings via API
│   └── scanner_mapper.py     # Detect scanner format for import
└── outputs/.gitkeep
```

## Integration

Works with all pentest agents:
- `/pentest` → findings imported to DefectDojo engagement
- `/hackerone` → bug bounty findings synced to DD for tracking
- `/intigriti` → same as above with Intigriti metadata
- `/hexstrike` → automated scan results imported via reimport

## Requirements

- DefectDojo instance with API v2 enabled
- API key with create permissions (findings, engagements, products)
- `curl` and `python3` (standard tools)

## Usage Examples

```bash
# Import pentest findings
/defectdojo "ACME Corp" "Q1 2026 Pentest"

# Import scanner results
python tools/scanner_mapper.py nuclei-results.json 5

# Bulk import findings
python tools/finding_importer.py outputs/pentest-acme/findings/ 1
```
