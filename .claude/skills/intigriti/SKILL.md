---
name: intigriti
description: Intigriti bug bounty automation - parses program scope from user-provided data (PDF, URL, manual input), deploys parallel pentesting agents for domain-based assets with tier prioritization, auto-downloads mobile apps from running emulators, validates PoCs, and generates Intigriti-formatted submission reports with vulnerability type taxonomy. Use when testing Intigriti programs or preparing European bug bounty submissions.
---

# Intigriti Bug Bounty Hunting

Automates Intigriti workflows: scope parsing → mobile app acquisition → recon → testing via /pentest → PoC validation → submission reports.

## Database Integration (MANDATORY)

All engagement data is persisted via the **Bounty Intel MCP tools** (`bounty_*`). These tools are auto-loaded when Claude starts in this project — no imports or env setup needed.

### At engagement start:
- `bounty_upsert_program(platform="intigriti", handle="{company}/{program}", company_name=..., scope=..., tech_stack=[...])`
- `bounty_create_engagement(program_id=..., notes="Initial scope assessment")`
- `bounty_update_engagement(engagement_id=..., recon_data=..., attack_surface=...)`
- `bounty_log_activity(action="engagement_started", engagement_id=..., details={...})`

### After each finding:
- `bounty_save_finding(program_id=..., engagement_id=..., title=..., vuln_class=..., severity=..., cvss_vector=..., description=..., steps_to_reproduce=..., impact=..., poc_code=..., poc_output=...)`
- `bounty_record_hunt(target=..., vuln_class=..., success=True, technique=..., tech_stack=[...], platform="intigriti")`
- `bounty_upload_evidence(finding_id=..., filename=..., local_path=...)` for screenshots/videos

### For building blocks:
- `bounty_save_finding(..., is_building_block=True, building_block_notes="Chain with OAuth token theft")`

### For submission reports:
- `bounty_create_report(program_id=..., platform="intigriti", title=..., markdown_body=..., finding_id=..., severity=..., report_slug="INTI_HIGH_001")`

### Context queries:
- `bounty_get_findings(program_id=...)` — check what's already been found
- `bounty_search_findings(query="SSRF")` — search across all findings
- `bounty_get_program(program_id=...)` — get scope and OOS rules
- `bounty_get_recon(program_id=...)` — get recon data
- `bounty_suggest_attacks(tech_stack=[...])` — get attack suggestions from hunt memory

### View reports before submission:
Reports are reviewed at https://bounty-dashboard-887002731862.europe-west1.run.app/reports — the user approves submission from the dashboard.

## Quick Start

```
1. Input: Intigriti program URL, PDF, or manual scope description
2. Register engagement in DB: db.upsert_program() + db.create_engagement()
3. If URL provided and $INTIGRITI_PAT is set:
   → Resolve program handle to ID via Researcher API
   → Fetch domains, tiers, rules of engagement, and testing requirements
   → Extract testingRequirements (User-Agent, headers) for scope contract
3. Parse scope: extract assets, tiers, types, and program rules
4. Generate scope.json: `python3 tools/scope_checker.py generate --domains '<in-scope>' --oos '<oos>' --output outputs/intigriti-{program}/scope.json`
5. For mobile assets: use /mobile-app-acquisition to detect emulators and download apps
6. Run /bounty-recon for prioritization + recon pipeline (recon only, no agent deployment)
7. **Autopilot decision**: Ask user — "Autopilot mode? (paranoid/normal/yolo/no)". If yes → invoke `/autopilot`. If no → invoke `/pentest` directly.
9. Invoke /pentest in sub-orchestrator mode OR /autopilot (testing engine)
10. MANDATORY: Invoke /bounty-validation skill for PoC validation + pre-submission gate + AI compliance
11. Save validated findings to DB: db.save_finding() + db.upload_evidence() + db.record_hunt()
12. Generate Intigriti-formatted reports to DB: db.create_report() (only after /bounty-validation passes)
13. Direct user to dashboard to review and approve submissions
```

## Scope Input Methods

**Option 1: Program URL via Researcher API** (recommended)
```
- [ ] User provides Intigriti program URL (e.g., https://app.intigriti.com/programs/<company>/<handle>/detail)
- [ ] Extract program handle from URL
- [ ] Resolve handle to programId: GET /v1/programs?limit=500, match by handle field
- [ ] Fetch program details: GET /v1/programs/{programId}
      → Returns: domains (assets with type, tier, endpoint), rules of engagement, status, bounty range
- [ ] Fetch full domains: GET /v1/programs/{programId}/domains/{versionId}
      → Returns: each domain with id, type, endpoint, tier, description, requiredSkills
- [ ] Fetch rules: GET /v1/programs/{programId}/rules-of-engagements/{versionId}
      → Returns: description, testingRequirements (automatedTooling, userAgent, requestHeader), safeHarbour, attachments
- [ ] Parse into structured scope for agent deployment
```

**Researcher API Configuration:**
```
Base URL: https://api.intigriti.com/external/researcher
Auth:     Authorization: Bearer $INTIGRITI_PAT
Version:  v1 (BETA)
```

**Key API Endpoints:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | /v1/programs | List all accessible programs (filter: statusId, typeId, following) |
| GET | /v1/programs/{programId} | Program details with domains and rules |
| GET | /v1/programs/{programId}/domains/{versionId} | Full domain/asset list for a version |
| GET | /v1/programs/{programId}/rules-of-engagements/{versionId} | Rules, testing requirements, attachments |
| GET | /v1/programs/activities | Program change events (scope updates, rule changes) |

**API Response → Scope Mapping:**
- `domains[].endpoint` → Asset name (domain, wildcard, app bundle)
- `domains[].type.value` → Asset type (Web Application, API, iOS, Android, etc.)
- `domains[].tier.value` → Tier (1-5, Tier 1 = highest bounty)
- `domains[].description` → Per-asset testing instructions
- `rulesOfEngagement.content.description` → Program rules, OOS list, bounty table
- `rulesOfEngagement.content.testingRequirements.userAgent` → Required User-Agent header
- `rulesOfEngagement.content.testingRequirements.requestHeader` → Required custom request header
- `rulesOfEngagement.content.testingRequirements.automatedTooling` → Automated tool policy
- `rulesOfEngagement.content.safeHarbour` → Safe harbour status

**Handle Resolution from URL:**
```bash
# Extract handle from URL: https://app.intigriti.com/programs/<company>/<handle>/detail
HANDLE=$(echo "$URL" | grep -oP 'programs/[^/]+/\K[^/]+')

# Resolve to programId via API
curl -s -H "Authorization: Bearer $INTIGRITI_PAT" \
  "https://api.intigriti.com/external/researcher/v1/programs?limit=500" \
  | jq -r ".records[] | select(.handle == \"$HANDLE\") | .id"
```

**Option 2: PDF of program page**
```
- [ ] Read PDF with program details
- [ ] Extract assets table (name, type, tier)
- [ ] Extract bounty table, rules, out-of-scope items
- [ ] Parse into structured scope for agent deployment
```

**Option 3: Program URL (browser scraping fallback)**
```
- [ ] Use when API is unavailable or PAT not configured
- [ ] Use Playwright MCP or browser tools to load the page
- [ ] Extract scope table, bounty table, and rules
- [ ] Parse into structured scope
```

**Option 4: Manual input**
```
- [ ] AskUserQuestion: "Provide the in-scope assets (domain/app, type, tier):"
- [ ] AskUserQuestion: "Any specific program rules or exclusions?"
- [ ] Build scope from user responses
```

## Scope Format

Intigriti uses domain-based scope (not CSV like HackerOne):
- **Asset name**: Target domain, wildcard, app bundle ID, or description
- **Type**: Web Application, API, iOS, Android, Device, Network
- **Tier**: 1-5 (Tier 1 = highest bounty)
- **Instructions**: Per-asset testing guidelines

Use `tools/scope_parser.py` to parse structured scope data.

## /pentest Invocation

After `/bounty-recon` completes recon, invoke `/pentest` in sub-orchestrator mode with:

```yaml
targets: # parsed from Researcher API domains
  - url: "https://target.com"
    type: "web-app"  # from domains[].type.value
    tier: 1           # from domains[].tier.value (1=highest bounty)
    restrictions: "from domain description"
engagement_name: "intigriti-{program-handle}"
output_base: "outputs/intigriti-{program}/"
context:
  platform: "intigriti"
  bounty_table: {} # parsed from program rules
  oos_list: [] # parsed from rules of engagement
  test_types: ["dast"] # bounty programs are dynamic testing
  scope_file: "outputs/intigriti-{program}/scope.json" # generated from API/PDF for deterministic scope checking
  testing_requirements:
    user_agent: "from testingRequirements.userAgent"
    request_header: "from testingRequirements.requestHeader"
  recon_path: "outputs/intigriti-{program}/processed/reconnaissance/"
  testing_recommendations: "outputs/intigriti-{program}/processed/reconnaissance/testing_recommendations.md"
```

**CRITICAL**: `testing_requirements` from the Researcher API MUST be propagated to all executors. `/pentest` passes these to every agent as mandatory request context.

`/pentest` runs Phase 3 (user approves attack plan), Phase 4 (deploy executors), Phase 5 (aggregate findings). Findings land in `outputs/intigriti-{program}/processed/findings/`.

## Shared Workflows

- **Prioritization + Recon**: See `/bounty-recon` (produces recon data + testing_recommendations.md)
- **Testing Engine**: See `/pentest` (sub-orchestrator mode — receives scope contract, runs Phase 3-5)
- **Mobile App Download**: See `/mobile-app-acquisition`
- **Validation + Compliance + Quality**: See `/bounty-validation`

## Report Format

Required fields (Intigriti standard):
1. **Title** (vulnerability description, no URL, **max 72 characters**)
2. **Severity** (CVSS v3.1 or v4.0 vector + score)
3. **CWE** (e.g., CWE-601, CWE-79 — must appear in report Type field)
4. **Domain** (affected in-scope asset)
5. **Vulnerability Type** (from Intigriti taxonomy dropdown)
6. **Description** (Markdown, detailed explanation)
7. **Steps to Reproduce** (numbered, clear)
8. **Impact** (realistic attack scenario)
9. **Raw HTTP requests/responses** (text format, supplementary to visual evidence)
10. **Visual evidence** (Playwright screenshots for browser-renderable vulns, real curl/tool output for server-side — see `/bounty-validation` Visual Evidence Standard)
11. **Role used** (e.g., user, admin, guest, unauthenticated)
12. **AI Disclosure** (MANDATORY — see `/bounty-validation` AI Usage Compliance)

Use `tools/report_validator.py` to validate.

## Output Structure

**PRIMARY**: All findings, reports, and engagement data stored in the **Bounty Intel database** via `bounty_*` MCP tools. Dashboard at `https://bounty-dashboard-887002731862.europe-west1.run.app` for review and approval.

**SECONDARY** (ephemeral only): Temp directory during active testing.

```
Database (primary):
  programs → scope, tech stack, metadata
  engagements → recon data, attack surface, status
  findings → description, PoC, evidence (GCS)
  submission_reports → platform-ready markdown, approval status
  hunt_memory → cross-target patterns

Local (ephemeral):
  outputs/intigriti-{program}/
  ├── apps/         # Downloaded mobile apps (temp)
  └── temp/         # Tool output, curl captures (temp)
```

## Platform Differences (vs HackerOne)

| Aspect | Intigriti | HackerOne |
|--------|-----------|-----------|
| Scope format | Domain-based (tiers, types) | CSV file |
| Scope retrieval | Researcher API (PAT) / PDF / URL / manual | CSV download / API |
| Triage | Managed by Intigriti team | Company-triaged |
| Currency | EUR | USD |
| Vuln classification | Taxonomy dropdown | Free-text |
| Bounty tiers | 1-5 (Tier 1 highest) | Per-severity |
| Report title | No URL in title | URL in title |

See `reference/PLATFORM_GUIDE.md` for full comparison.

## Critical Rules

**MUST DO**:
- When a program URL is provided, use the Researcher API with `$INTIGRITI_PAT` to fetch scope (preferred over scraping)
- If `$INTIGRITI_PAT` is not set, ask the user for it or fall back to PDF/scraping/manual input
- Apply `testingRequirements` from the API (User-Agent, custom headers) to all testing agents
- Parse scope from user-provided program data (API, PDF, URL, or manual input)
- Test only in-scope assets
- Follow program-specific rules
- Include CVSS vector string
- Select correct vulnerability type from taxonomy
- **Invoke /bounty-validation skill BEFORE declaring any report ready for submission** — ad-hoc validation is NOT a substitute

**NEVER**:
- Report without validated PoC
- Test out-of-scope assets or cause service disruption
- Include real user data
- Declare reports "ready to submit" without having invoked /bounty-validation first

## Tools

- `bounty_*` MCP tools - **Primary persistence** (findings, reports, hunt memory, activity, evidence)
- `tools/scope_parser.py` - Parse Intigriti scope from structured data
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

## Usage

```
/intigriti <program_pdf_or_url>
```
