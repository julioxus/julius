---
name: hackerone
description: HackerOne bug bounty automation - parses scope CSVs, deploys parallel pentesting agents for each asset, auto-downloads mobile apps from running emulators, validates PoCs, and generates platform-ready submission reports. Use when testing HackerOne programs or preparing professional vulnerability submissions.
---

# HackerOne Bug Bounty Hunting

Automates HackerOne workflows: scope parsing → mobile app acquisition → recon → testing via /pentest → PoC validation → submission reports.

## Quick Start

```
1. Input: HackerOne program URL or CSV file
2. Parse scope and program guidelines
3. For mobile assets: use /mobile-app-acquisition to detect emulators and download apps
4. Run /bounty-recon for prioritization + recon pipeline (recon only, no agent deployment)
5. Invoke /pentest in sub-orchestrator mode (testing engine)
6. MANDATORY: Invoke /bounty-validation skill for PoC validation + pre-submission gate + AI compliance
   → This is NOT optional. Do NOT declare reports ready without running this skill.
   → /bounty-validation enforces: anti-hallucination checks, AI disclosure, evidence quality, OOS checks
7. Generate HackerOne-formatted reports (only after /bounty-validation passes)
```

## Workflows

**Option 1: HackerOne URL**
```
- [ ] Fetch program data and guidelines
- [ ] Download scope CSV
- [ ] Parse eligible assets into scope contract
- [ ] Run /bounty-recon (recon only → testing_recommendations.md)
- [ ] Invoke /pentest with scope contract (Phase 3-5)
- [ ] Run /bounty-validation on findings
- [ ] Generate HackerOne submission reports
```

**Option 2: CSV File**
```
- [ ] Parse CSV scope file
- [ ] Extract eligible_for_submission=true assets
- [ ] Collect program guidelines
- [ ] Run /bounty-recon (recon only → testing_recommendations.md)
- [ ] Invoke /pentest with scope contract (Phase 3-5)
- [ ] Run /bounty-validation on findings
- [ ] Generate HackerOne submission reports
```

## /pentest Invocation

After `/bounty-recon` completes recon, invoke `/pentest` in sub-orchestrator mode with:

```yaml
targets: # parsed from CSV eligible assets
  - url: "https://target.com"
    type: "web-app"
    tier: 1  # derived from max_severity
    restrictions: "from CSV instruction field"
engagement_name: "{program-name}"
output_base: "outputs/{program}/"
context:
  platform: "hackerone"
  bounty_table: {} # parsed from program page
  oos_list: [] # parsed from program scope
  test_types: ["dast"] # bounty programs are dynamic testing
  recon_path: "outputs/{program}/processed/reconnaissance/"
  testing_recommendations: "outputs/{program}/processed/reconnaissance/testing_recommendations.md"
```

`/pentest` runs Phase 3 (user approves attack plan), Phase 4 (deploy executors), Phase 5 (aggregate findings). Findings land in `outputs/{program}/processed/findings/`.

## Scope CSV Format

Expected columns:
- `identifier` - Asset URL/domain
- `asset_type` - URL, WILDCARD, API, CIDR
- `eligible_for_submission` - Must be "true"
- `max_severity` - critical, high, medium, low
- `instruction` - Asset-specific notes

Use `tools/csv_parser.py` to parse.

## Shared Workflows

- **Prioritization + Recon**: See `/bounty-recon` (produces recon data + testing_recommendations.md)
- **Testing Engine**: See `/pentest` (sub-orchestrator mode — receives scope contract, runs Phase 3-5)
- **Mobile App Download**: See `/mobile-app-acquisition`
- **Validation + Compliance + Quality**: See `/bounty-validation`

## Report Format — Inline Writeup Style (MANDATORY)

Reports MUST use **writeup format**: screenshots and evidence embedded inline within Steps to Reproduce, immediately after the step they demonstrate. NEVER put evidence in a table or section at the end. The report reads as a self-contained narrative walkthrough where each claim is backed by visual proof.

Required sections (HackerOne standard):
1. Summary (2-3 sentences)
2. Severity (CVSS + business impact)
3. CWE (e.g., CWE-601, CWE-79 — must appear in report)
4. Steps to Reproduce — numbered, with **inline evidence** (`![caption](evidence/file.png)` after each step)
5. Raw HTTP requests/responses (real curl -v output, not reconstructed)
6. Visual Evidence **embedded inline** (Playwright screenshots for browser vulns, terminal captures for server-side — see `/bounty-validation` Visual Evidence Standard). Each screenshot placed immediately after the step it proves.
7. Impact (realistic attack scenario)
8. Remediation (actionable fixes)
9. AI Disclosure (MANDATORY — see `/bounty-validation` AI Usage Compliance)

**Example inline evidence format:**
```markdown
### Step 2: Trigger the vulnerability
` ` `bash
curl -X POST https://target.com/api/endpoint ...
` ` `
**Expected**: HTTP 403  |  **Actual**: HTTP 200
![Server returned internal metadata](evidence/02_ssrf_response.png)
```

Use `tools/report_validator.py` to validate.

## Output Structure

Per OUTPUT.md - Bug Bounty format:

```
outputs/<program>/
├── apps/                         # Downloaded mobile apps
│   ├── <package>.apk
│   └── <bundle>.ipa
├── findings/
│   ├── finding-001/
│   │   ├── report.md           # HackerOne report
│   │   ├── poc.py              # Validated PoC
│   │   ├── poc_output.txt      # Proof
│   │   ├── workflow.md         # Manual steps
│   │   └── evidence/           # Per-finding evidence
│   │       ├── screenshot-*.png # Playwright browser captures
│   │       ├── curl-*.txt       # Real curl -v output
│   │       └── raw-source.txt   # Raw tool output
├── reports/
│   ├── submissions/
│   │   ├── H1_CRITICAL_001.md  # Ready to submit
│   │   └── H1_HIGH_001.md
│   └── SUBMISSION_GUIDE.md
└── evidence/                   # Shared engagement evidence
    ├── screenshots/
    └── http-logs/
```

## Program Selection

**High-Value**:
- New programs (< 30 days)
- Fast response (< 24 hours)
- High bounties (Critical: $5,000+)
- Large attack surface

**Avoid**:
- Slow response (> 1 week)
- Low bounties (Critical: < $500)
- Overly restrictive scope

## Critical Rules

**MUST DO**:
- Validate ALL PoCs before reporting
- Sanitize sensitive data
- Test only `eligible_for_submission=true` assets
- Follow program-specific guidelines
- Compute CVSS scores using a calculator (Python/bash), never guess or estimate
- **Invoke /bounty-validation skill BEFORE declaring any report ready for submission** — ad-hoc validation is NOT a substitute

**NEVER**:
- Report without validated PoC
- Test out-of-scope assets
- Include real user data
- Cause service disruption
- Declare reports "ready to submit" without having invoked /bounty-validation first

## Tools

- `tools/csv_parser.py` - Parse HackerOne scope CSVs
- `tools/report_validator.py` - Validate report completeness
- `/pentest` skill - Testing engine (invoked in sub-orchestrator mode)
- `/bounty-recon` skill - Recon pipeline + testing recommendations
- `/bounty-validation` skill - Validation + compliance + quality
- `/mobile-app-acquisition` skill - Mobile app download from emulators
- `/mobile-security` skill - Mobile app analysis
- `/burp-suite` skill - Active scanning, Collaborator OOB testing (via bounty-recon)
- `/hexstrike` skill - 150+ security tools for parallel recon and testing
- `/authenticating` skill - Auth bypass, 2FA, CAPTCHA testing
- `dom-xss-scanner` agent - Automated DOM XSS via Playwright (auto for JS targets)
- **Utility agents**: `patt-fetcher`, `script-generator`, `pentester-validator`

## Integration

Invokes `/pentest` in sub-orchestrator mode as testing engine. Uses `/bounty-recon` for recon and `/bounty-validation` for quality gate. Follows OUTPUT.md for submission format.

## Common Rejections

**Out of Scope**: Check `eligible_for_submission=true`
**By Design / Not a Bug**: The reported behavior is the intended functionality of the service. ALWAYS verify business logic before reporting — understand what the company does and whether the "vulnerability" is actually their core product feature.
**Cannot Reproduce**: Validate PoC, include poc_output.txt
**Duplicate**: Search disclosed reports, submit quickly
**Insufficient Impact**: Show realistic attack scenario

## Usage

```bash
/hackerone <program_url_or_csv_path>
```
