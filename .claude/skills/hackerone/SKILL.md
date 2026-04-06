---
name: hackerone
description: HackerOne bug bounty automation - parses scope CSVs, deploys parallel pentesting agents for each asset, auto-downloads mobile apps from running emulators, validates PoCs, and generates platform-ready submission reports. Use when testing HackerOne programs or preparing professional vulnerability submissions.
---

# HackerOne Bug Bounty Hunting

Automates HackerOne workflows: scope parsing → mobile app acquisition → recon → testing via /pentest → PoC validation → submission reports.

## Database Integration (MANDATORY)

All engagement data is persisted via the **Bounty Intel REST API** — no direct database access. The API is served by the Cloud Run dashboard. Skills only need `BOUNTY_INTEL_API_KEY` in `.env`.

```python
from bounty_intel.client import BountyIntelClient
api = BountyIntelClient()  # reads BOUNTY_INTEL_API_URL + BOUNTY_INTEL_API_KEY from .env
```

### At engagement start:
```python
program_id = api.upsert_program(platform="hackerone", handle=program_handle, company_name=company_name, scope=scope_json, tech_stack=detected_tech)
engagement_id = api.create_engagement(program_id, notes="Initial scope assessment", recon_data=recon_results, attack_surface=surface_map)
api.log_activity(engagement_id, "engagement_started", {"program": program_handle, "assets": len(targets)})
```

### After each finding:
```python
finding_id = api.save_finding(
    engagement_id=engagement_id, program_id=program_id,
    title="SSRF via redirect parameter", vuln_class="SSRF", severity="High",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    description="Full markdown description...", steps_to_reproduce="Steps...",
    impact="Impact statement...", poc_code="python3 poc script...", poc_output="timestamped output..."
)
api.record_hunt(target="target.com", vuln_class="SSRF", success=True, technique="Open redirect → SSRF", tech_stack=["Flask"], platform="hackerone")
api.log_activity(engagement_id, "finding_created", {"finding_id": finding_id, "title": "SSRF via redirect"})
```

### For submission reports (replaces writing H1_*.md files):
```python
report_id = api.create_report(
    finding_id=finding_id, program_id=program_id, platform="hackerone",
    report_slug="H1_HIGH_001", title="SSRF via redirect parameter",
    severity="High", cvss_vector="CVSS:3.1/...", markdown_body=full_report_markdown
)
api.log_activity(engagement_id, "report_created", {"report_id": report_id, "slug": "H1_HIGH_001"})
```

### For building blocks (findings that can't be submitted alone):
```python
api.save_finding(
    engagement_id=engagement_id, program_id=program_id,
    title="Open redirect on login callback", vuln_class="open_redirect", severity="Low",
    is_building_block=True, building_block_notes="Chain with SSRF or OAuth token theft",
    description="...", poc_code="...", poc_output="..."
)
```

### View reports before submission (dashboard):
Reports are reviewed at https://bounty-dashboard-887002731862.europe-west1.run.app/reports — the user approves submission from the dashboard. NEVER submit directly to HackerOne without user approval via the dashboard.

## Quick Start

```
1. Input: HackerOne program URL or CSV file
2. Parse scope and program guidelines
3. Register engagement in DB: db.upsert_program() + db.create_engagement()
4. For mobile assets: use /mobile-app-acquisition to detect emulators and download apps
5. Run /bounty-recon for prioritization + recon pipeline (recon only, no agent deployment)
6. **Autopilot decision**: Ask user — "Autopilot mode? (paranoid/normal/yolo/no)". If yes → invoke `/autopilot`. If no → invoke `/pentest` directly.
7. Invoke /pentest in sub-orchestrator mode OR /autopilot (testing engine)
8. MANDATORY: Invoke /bounty-validation skill for PoC validation + pre-submission gate + AI compliance
9. Save validated findings to DB: db.save_finding() + db.upload_evidence() + db.record_hunt()
10. Generate HackerOne-formatted reports to DB: db.create_report() (only after /bounty-validation passes)
11. Direct user to dashboard to review and approve submissions
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
- [ ] Generate scope.json: `python3 tools/scope_checker.py generate --domains '<in-scope>' --oos '<oos>' --output outputs/hackerone-{program}/scope.json`
- [ ] Run /bounty-recon (recon only → testing_recommendations.md)
- [ ] Invoke /pentest with scope contract (Phase 3-5, includes scope_file)
- [ ] Run /bounty-validation on findings
- [ ] Record validated findings: `python3 tools/hunt_memory.py record ...` for each finding
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
output_base: "outputs/hackerone-{program}/"
context:
  platform: "hackerone"
  bounty_table: {} # parsed from program page
  oos_list: [] # parsed from program scope
  test_types: ["dast"] # bounty programs are dynamic testing
  recon_path: "outputs/hackerone-{program}/processed/reconnaissance/"
  testing_recommendations: "outputs/hackerone-{program}/processed/reconnaissance/testing_recommendations.md"
  scope_file: "outputs/hackerone-{program}/scope.json" # generated from CSV for deterministic scope checking
```

`/pentest` runs Phase 3 (user approves attack plan), Phase 4 (deploy executors), Phase 5 (aggregate findings). Findings land in `outputs/hackerone-{program}/processed/findings/`.

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

**PRIMARY**: All findings, reports, and engagement data are stored in the **Bounty Intel database** via `BountyIntelClient`. The dashboard at `https://bounty-dashboard-887002731862.europe-west1.run.app` is the operations center for reviewing and approving submissions.

**SECONDARY** (ephemeral only): A temporary local directory `outputs/hackerone-{program}/` can be used for artifacts during active testing (tool output, temp files), but nothing should persist there long-term. All validated findings and reports MUST be saved to the database.

```
Database (primary):
  programs → engagement metadata, scope, tech stack
  engagements → recon data, attack surface, status
  findings → full finding with description, PoC, evidence (GCS)
  submission_reports → platform-ready markdown, approval status
  hunt_memory → what worked/failed for future reference

Local (ephemeral, during active testing only):
  outputs/hackerone-{program}/
  ├── apps/                    # Downloaded mobile apps (temp)
  └── temp/                    # Tool output, curl captures (temp)
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

- `bounty_intel.client.BountyIntelClient` - **Primary persistence** (findings, reports, hunt memory, activity)
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
- **Dashboard**: https://bounty-dashboard-887002731862.europe-west1.run.app — report review + approval

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
