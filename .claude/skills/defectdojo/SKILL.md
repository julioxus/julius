---
name: defectdojo
description: DefectDojo vulnerability management automation - authenticates via API, creates products/engagements, imports pentest findings with CWE mapping, uploads evidence, and syncs validated PoCs. Use when reporting findings to DefectDojo or managing vulnerability lifecycle.
---

# DefectDojo Vulnerability Reporting

Automates DefectDojo workflows: API auth → product/engagement setup → finding import → evidence upload → validation.

## API Authentication (MANDATORY - ALWAYS FIRST)

**All operations MUST use the DefectDojo REST API v2. Never hardcode credentials.**

```
1. Check for DEFECTDOJO_URL and DEFECTDOJO_TOKEN env vars
2. If behind IAP → also check IAP_CLIENT_ID env var
3. If NOT set → AskUserQuestion:
   question: "DefectDojo config missing. Provide instance URL and API key."
   options: ["I'll provide them now", "Help me find the API key"]
4. If "Help" → Show: {DEFECTDOJO_URL}/api/key-v2 (Profile → API Key)
5. Validate (with IAP if configured):
   python tools/iap_browser_auth.py  # obtains token via cache/gcloud/browser
   curl -s -o /dev/null -w "%{http_code}" \
     -H "Authorization: Token $DEFECTDOJO_TOKEN" \
     -H "Proxy-Authorization: Bearer <iap_token>" \
     $DEFECTDOJO_URL/api/v2/users/me/
6. If != 200 → Ask again. Do NOT proceed.
```

**IAP Authentication** (for instances behind Google Cloud Identity-Aware Proxy):

The skill uses Playwright browser automation via `tools/iap_browser_auth.py`:
1. **Cached cookies** — reads from `~/.defectdojo/iap_cookies.txt` if still valid (~1h TTL)
2. **Playwright browser login** — launches Chromium, navigates to DefectDojo,
   user authenticates via Google/IAP, cookies extracted automatically after login

No `IAP_CLIENT_ID` or `IAP_CLIENT_SECRET` needed — just browser login.
Requires: `pip install playwright && playwright install chromium`

```
# Only env vars needed
export DEFECTDOJO_URL=https://defectdojo.internal
export DEFECTDOJO_TOKEN=<your_api_key>
```

**Cookie management:**
```
# Authenticate via browser (opens DefectDojo, prompts for cookies)
python tools/iap_browser_auth.py

# Check cached cookie status
python tools/iap_browser_auth.py --status

# Clear cached cookies (force re-auth on next call)
python tools/iap_browser_auth.py --clear
```

**NEVER skip API authentication. NEVER proceed without validated credentials.**

## Quick Start

```
1. Validate DEFECTDOJO_URL + DEFECTDOJO_TOKEN (see above)
2. Input: Product name + engagement name (or IDs)
3. Create product/engagement if needed
4. Scan outputs/ for validated findings
5. Map findings → CWE + DefectDojo severity
6. Import via API with evidence uploads
7. Verify import and present summary
```

## Workflows

**Option 1: Import from Pentest Engagement**
```
- [ ] Validate API credentials (mandatory)
- [ ] Identify product and engagement (search existing via API)
- [ ] **If product/engagement need to be created → AskUserQuestion for approval first**
- [ ] Scan outputs/{engagement}/findings/ for validated findings
- [ ] **Verify real impact for EVERY finding** — reproduce with working PoC against a live/local instance, capture evidence. No PoC = No import. Same standard as bug bounty programs.
   - [ ] **Require pentester-validator PASS** — only import findings that passed all 5 anti-hallucination checks (CVSS consistency, evidence exists, PoC validation, claims vs raw evidence, log corroboration). Check for `validated/{finding_id}.json` in the output. Findings in `false-positives/` MUST NOT be imported.
- [ ] **Format each finding per DefectDojo schema** — title, CWE, CVSS vector+score, endpoint, description, impact, steps_to_reproduce, mitigation (see Finding Format section). All fields mandatory.
- [ ] Map vulnerability types → CWE IDs (reference/CWE_MAPPING.md)
- [ ] Deduplicate against existing findings
- [ ] **Present findings summary table to user (title, severity, CWE, PoC status)**
- [ ] **AskUserQuestion: get explicit approval before importing**
- [ ] Create/find test "Manual Review" (type "Manual Code Review") in engagement via /api/v2/tests/
- [ ] Import ONLY approved findings via POST /api/v2/findings/ (linked to the Manual Review test)
- [ ] Upload evidence (screenshots, PoCs, HTTP logs)
- [ ] Verify and present summary
```

**Option 2: Import from Scanner Output**
```
- [ ] Validate API credentials (mandatory)
- [ ] Identify product and engagement (search existing via API)
- [ ] **If product/engagement need to be created → AskUserQuestion for approval first**
- [ ] Detect scanner format and show user what will be imported
- [ ] **AskUserQuestion: get explicit approval before importing scan**
- [ ] Use reimport endpoint for supported formats:
  POST /api/v2/reimport-scan/ (Nuclei, Nmap, ZAP, Burp, etc.)
- [ ] Verify imported findings
- [ ] Present summary
```

**Option 3: Sync Bug Bounty Findings**
```
- [ ] Validate API credentials (mandatory)
- [ ] Read findings from outputs/hackerone-* or outputs/intigriti-*
- [ ] **Require pentester-validator PASS for all findings** — skip any without validated/{finding_id}.json
- [ ] **AskUserQuestion: confirm product/engagement creation before proceeding**
- [ ] Create product per program, engagement per campaign (only after approval)
- [ ] **Present all findings to user for review**
- [ ] **AskUserQuestion: get explicit approval before importing**
- [ ] Import ONLY approved findings with platform-specific metadata as notes
- [ ] Upload submission reports as evidence
```

**Option 4: Import CVE PoC Generator Findings**
```
- [ ] Validate API credentials (mandatory)
- [ ] Read findings from outputs/processed/cve-pocs/CVE-XXXX-XXXXX/
- [ ] Parse poc.py + report.md (generated by /cve-poc-generator)
- [ ] Extract: CVE ID, CVSS vector+score from NVD data, CWE ID, affected versions
- [ ] Map to DefectDojo format: title="CVE-XXXX-XXXXX: <description>", CWE from report
- [ ] **AskUserQuestion: confirm product/engagement before proceeding**
- [ ] **Present findings summary and get explicit approval**
- [ ] Import with poc.py as evidence, report.md content in description
- [ ] Tag findings with CVE ID for deduplication
```

## Finding Format (MANDATORY)

Every finding MUST include ALL of these fields before import. Missing fields = do not import.

**Markdown formatting**: All text fields (`description`, `impact`, `steps_to_reproduce`, `mitigation`) are rendered as **Markdown** in the DefectDojo UI. Always use proper markdown: `### Headers` for sections, `` ```python ``/`` ```bash `` for code blocks, `| col | col |` for tables, `**bold**` for emphasis, `> quotes` for results, and `-` for lists. Never use plain text formatting — it will render poorly.

**Cross-references between findings**: When a finding references another finding, ALWAYS use a markdown link with the DefectDojo finding URL: `[Finding #1234](https://dojo.example.com/finding/1234)`. This means findings that are referenced by others MUST be created first. **Plan the import order so that dependencies are created before dependents** — e.g., if Finding B references Finding A, create Finding A first, get its DefectDojo ID, then use that URL when creating Finding B.

**No abbreviations — match local reports exactly**: The DefectDojo finding MUST contain the same level of detail as the local report (`outputs/*/findings/finding-NNN/report.md`). Never summarize, shorten, or omit content when importing to DefectDojo. Include all code snippets, all PoC commands, all HTTP responses, all tables, and all evidence from the local report. Full URLs, full paths, full commands — never use `...` or ellipsis.

| Field | DefectDojo API field | Format | Required |
|-------|---------------------|--------|----------|
| **Title** | `title` | `Short description` (no CWE prefix) | YES |
| **CWE** | `cwe` | Integer ID (see reference/CWE_MAPPING.md) | YES |
| **CVSS Vector** | `cvssv3` | Full `CVSS:3.1/AV:.../...` string | YES |
| **CVSS Score** | `cvssv3_score` | Numeric (0.0-10.0), **MUST be computed with a calculator (Python/bash), never guessed** | YES |
| **Severity** | `severity` | Critical(9.0-10.0)/High(7.0-8.9)/Medium(4.0-6.9)/Low(0.1-3.9)/Info(0.0) — MUST match CVSS score, never override manually | YES |
| **Endpoint** | `endpoints` | Affected URL/path/component | YES |
| **Description** | `description` | Technical explanation of the vulnerability. **MUST include affected components and endpoints** (e.g., file paths, API routes, infrastructure elements). | YES |
| **Impact** | `impact` | Real business impact (verified, not theoretical) | YES |
| **Steps to Reproduce** | `steps_to_reproduce` | Numbered steps with exact commands/requests | YES |
| **Mitigation** | `mitigation` | Actionable remediation guidance | YES |
| **Evidence** | file upload | Screenshots, PoC scripts, HTTP logs | YES |

## Engagement Types

- **Interactive**: Manual pentest (use for /pentest, /hackerone, /intigriti results)
- **CI/CD**: Automated scans (use for nuclei, ZAP, Burp scan imports)

## Supported Scanner Imports

DefectDojo reimport accepts 150+ formats. Common ones:
- `Nuclei Scan` | `Nmap XML` | `ZAP Scan` | `Burp REST API`
- `Trivy Scan` | `Prowler` | `Semgrep JSON`
- `Generic Findings Import` (CSV/JSON for custom formats)

Use `tools/scanner_mapper.py` to identify format from file.

## Output Structure

```
outputs/defectdojo-{product}/
├── reports/
│   └── defectdojo-import.json    # Import results with DD IDs
├── activity/
│   └── defectdojo-reporter.log   # NDJSON activity log
└── evidence/
    └── uploaded/                  # Tracking uploaded files
```

## Critical Rules

**MUST DO**:
- **Validate DEFECTDOJO_URL + DEFECTDOJO_TOKEN before any operation**
- **ASK USER APPROVAL BEFORE UPLOADING EACH FINDING** — present a summary table of all findings (title, severity, CWE) and use AskUserQuestion to get explicit confirmation before importing. NEVER auto-import findings without user consent.
- **CREATE FINDINGS UNDER A TEST** — always create/find a test named "Manual Review" with test type "Manual Code Review" in the engagement, then link all findings to that test ID.
- Map CWE IDs accurately (reference/CWE_MAPPING.md)
- Deduplicate against existing findings
- Upload all evidence files
- Verify import completeness

**NEVER**:
- **Proceed without validated API credentials**
- **Create or modify ANY resource in DefectDojo (product, engagement, test, finding) without explicit user approval first**
- **Import findings without validated PoC** — every finding MUST have a working proof-of-concept reproduced against a live/local instance with captured evidence, same standard as bug bounty programs
- **Import findings that failed pentester-validator** — check for `validated/{finding_id}.json` before import. If a finding is in `false-positives/`, it MUST NOT be imported regardless of user request
- Import fabricated or placeholder findings
- Overwrite existing findings without user approval
- Skip deduplication

## Tools

- `tools/iap_browser_auth.py` - IAP cookie acquisition via Playwright (cache → browser login)
- `tools/finding_importer.py` - Import findings to DefectDojo API
- `tools/scanner_mapper.py` - Map scanner output to DD import format
- `reference/CWE_MAPPING.md` - Vulnerability type → CWE ID mapping
- `reference/API_REFERENCE.md` - DefectDojo API v2 reference

## Usage

```
/defectdojo <product_name> [engagement_name]
```
