---
name: hackerone
description: HackerOne bug bounty automation - parses scope CSVs, deploys parallel pentesting agents for each asset, auto-downloads mobile apps from running emulators, validates PoCs, and generates platform-ready submission reports. Use when testing HackerOne programs or preparing professional vulnerability submissions.
---

# HackerOne Bug Bounty Hunting

Automates HackerOne workflows: scope parsing → mobile app acquisition → recon → testing via /pentest → PoC validation → submission reports.

## Database Integration (MANDATORY)

All engagement data is persisted via the **Bounty Intel MCP tools** (`bounty_*`). These tools are auto-loaded when Claude starts in this project — no imports or env setup needed.

### At engagement start:
- `bounty_upsert_program(platform="hackerone", handle=..., company_name=..., scope=..., tech_stack=[...])`
- `bounty_create_engagement(program_id=..., notes="Initial scope assessment")`
- `bounty_update_engagement(engagement_id=..., recon_data=..., attack_surface=...)`
- `bounty_log_activity(action="engagement_started", engagement_id=..., details={...})`

### After each finding:
- `bounty_save_finding(program_id=..., engagement_id=..., title=..., vuln_class=..., severity=..., cvss_vector=..., description=..., steps_to_reproduce=..., impact=..., poc_code=..., poc_output=...)`
- `bounty_record_hunt(target=..., vuln_class=..., success=True, technique=..., tech_stack=[...], platform="hackerone")`
- `bounty_upload_evidence(finding_id=..., filename=..., local_path=...)` for screenshots/videos
- `bounty_log_activity(action="finding_created", engagement_id=..., details={...})`

### For building blocks:
- `bounty_save_finding(..., is_building_block=True, building_block_notes="Chain with SSRF or OAuth token theft")`

### For submission reports:
- `bounty_create_report(program_id=..., platform="hackerone", title=..., markdown_body=..., finding_id=..., severity=..., report_slug="H1_HIGH_001")`
- `bounty_log_activity(action="report_created", engagement_id=..., details={...})`

### Context queries:
- `bounty_get_findings(program_id=...)` — check what's already been found
- `bounty_search_findings(query="SSRF")` — search across all findings
- `bounty_get_program(program_id=...)` — get scope and OOS rules
- `bounty_get_recon(program_id=...)` — get recon data
- `bounty_suggest_attacks(tech_stack=[...])` — get attack suggestions from hunt memory

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

## Report Format — Lean Writeup Style (MANDATORY)

**Reports that look AI-generated get closed.** Write like a human researcher: direct, concise, first-person. See `/bounty-validation` Report Writing Quality Gate for full rules.

### Writing Rules
- First person ("I found", "I tested") — never passive voice
- Under 500 words body text (excluding code blocks/HTTP dumps)
- NO filler sections (Description, Background, Remediation unless required)
- NO AI phrases: "This report details", "It's important to note", "leveraging", "poses a significant risk"
- Every word earns its place — if removing a sentence doesn't lose information, remove it
- **Every command in the report must have been executed and verified working** — never write commands from memory

### Required Sections
1. **Title**: `[VulnType] — [What] in [Where]` (under 80 chars)
2. **Summary**: 1-2 sentences. What's broken, why it matters.
3. **Severity**: CVSS vector + computed score + CWE
4. **Steps to Reproduce**: Numbered. Real URLs, real payloads. After each step: **real screenshot from Burp Suite or browser** (`![caption](evidence/stepN_desc.png)`)
5. **Impact**: 2-3 sentences. Concrete attacker gain. No speculation.
6. **AI Disclosure**: Brief, honest (see `/bounty-validation`)

### Screenshot Requirements (CRITICAL)
- Primary evidence = screenshots from **Burp Suite** (Repeater, HTTP history) or **browser** (DevTools, rendered page)
- Playwright screenshots are supplementary only
- If researcher hasn't provided screenshots: **BLOCK report generation** and ask for them
- No fabricated, reconstructed, or placeholder screenshots

### Example
```markdown
# SSRF — Internal metadata access via image proxy

## Summary
The image proxy at `/api/proxy` follows redirects to internal services. I accessed the cloud metadata endpoint and retrieved IAM credentials.

## Steps to Reproduce
1. I sent this request through Burp Repeater:
` ` `bash
curl -v "https://app.example.com/api/proxy?url=http://169.254.169.254/latest/meta-data/iam/"
` ` `
![Burp showing metadata response](evidence/step1_burp_ssrf.png)

2. The response contained IAM role names:
` ` `
role-web-prod
role-worker-prod
` ` `
![IAM credentials in response](evidence/step2_iam_creds.png)

## Impact
An attacker can read cloud metadata including IAM credentials, enabling lateral movement to other AWS services.

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N → 8.6 (High)
CWE-918
```

Use `tools/report_validator.py` to validate (includes anti-AI pattern checks).

## Output Structure

**PRIMARY**: All findings, reports, and engagement data are stored in the **Bounty Intel database** via `bounty_*` MCP tools. The dashboard at `https://bounty-dashboard-887002731862.europe-west1.run.app` is the operations center for reviewing and approving submissions.

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

## 🔒 MANDATORY VALIDATION REQUIREMENTS

Before ANY external communication (emails, reports, submissions):

```python
# REQUIRED AT TOP OF ALL SKILLS:
from tools.validation_gates import MandatoryValidator

# REQUIRED BEFORE ANY FINDING SUBMISSION:
try:
    MandatoryValidator.validate_finding_before_report(finding_data, engagement_name)
    print("✅ All validation gates passed")
except ValidationError as e:
    print(f"❌ VALIDATION FAILED: {e}")
    print("🚫 SUBMISSION BLOCKED - Fix issues before proceeding")
    return False
```

**Output Structure Compliance:**
- Evidence files → `outputs/{engagement}/reports/appendix/{finding-id}/`  
- PoC files → `outputs/{engagement}/processed/findings/{finding-id}/`
- Data files → `outputs/{engagement}/data/{type}/`
- Logs → `outputs/{engagement}/logs/`

**Emergency Halt Conditions:**
- All endpoints return identical responses
- OAuth without external redirects  
- Claims without end-to-end proof
- "Could lead to" without demonstration

```python
# MANDATORY: Use standardized output paths
from tools.validation_gates import get_output_path, validate_output_path

def write_evidence_file(engagement_name: str, finding_id: str, filename: str, content: str):
    evidence_path = get_engagement_output_path(engagement_name, "evidence", filename, finding_id)
    validate_output_path(evidence_path, engagement_name)
    # Ensure directory exists
    os.makedirs(os.path.dirname(evidence_path), exist_ok=True)
    with open(evidence_path, 'w') as f:
        f.write(content)

def write_finding_file(engagement_name: str, finding_id: str, filename: str, content: str):
    finding_path = get_engagement_output_path(engagement_name, "finding", filename, finding_id)
    validate_output_path(finding_path, engagement_name)
    # Ensure directory exists
    os.makedirs(os.path.dirname(finding_path), exist_ok=True)
    with open(finding_path, 'w') as f:
        f.write(content)
```

## Critical Rules

**MUST DO**:
- **ALWAYS run MandatoryValidator.validate_finding_before_report() before ANY external communication**
- **Use standardized output paths via get_engagement_output_path() function**
- Validate ALL PoCs before reporting
- Sanitize sensitive data
- Test only `eligible_for_submission=true` assets
- Follow program-specific guidelines
- Compute CVSS scores using a calculator (Python/bash), never guess or estimate
- **Invoke /bounty-validation skill BEFORE declaring any report ready for submission** — ad-hoc validation is NOT a substitute

**NEVER**:
- Report without running MandatoryValidator first
- Use hardcoded paths like "OUTPUT_DIR/", "output/", or "tmp/"
- Report without validated PoC
- Test out-of-scope assets
- Include real user data
- Cause service disruption
- Declare reports "ready to submit" without having invoked /bounty-validation first

## Tools

- `bounty_*` MCP tools - **Primary persistence** (findings, reports, hunt memory, activity, evidence)
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
