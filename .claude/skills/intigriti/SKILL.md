---
name: intigriti
description: Intigriti bug bounty automation - fetches program scope via API, deploys parallel pentesting agents for domain-based assets with tier prioritization, validates PoCs, and generates Intigriti-formatted submission reports with vulnerability type taxonomy. Use when testing Intigriti programs or preparing European bug bounty submissions.
---

# Intigriti Bug Bounty Hunting

Automates Intigriti workflows: API authentication → scope retrieval → tier-prioritized testing → PoC validation → submission reports.

## API Authentication (MANDATORY - ALWAYS FIRST)

**All scope and program data MUST be fetched via the Intigriti API. No manual/hardcoded scope allowed.**

```
1. Check for INTIGRITI_TOKEN env var: echo $INTIGRITI_TOKEN
2. If NOT set → AskUserQuestion:
   question: "Intigriti API token not found. Provide your Bearer token (Account Settings → API → Generate Token):"
   options: ["I'll provide it now", "Help me get one"]
3. If "Help me get one" → Show: https://app.intigriti.com/researcher/settings/api
4. Once provided → export INTIGRITI_TOKEN=<user_token>
5. Validate token: curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $INTIGRITI_TOKEN" -H "Content-Type: application/json" https://api.intigriti.com/external/researcher/v1/programs
6. If 401/403 → Ask user for valid token. Do NOT proceed.
7. If 200 → Continue to Quick Start
```

**NEVER skip API authentication. NEVER proceed without a validated token.**

## Quick Start

```
1. Validate INTIGRITI_TOKEN (see above)
2. Input: Intigriti program URL or program ID
3. Fetch scope via API (domain-based with tiers)
4. Deploy Pentester agents in parallel (tier-prioritized)
5. Validate PoCs (poc.py + poc_output.txt required)
6. Generate Intigriti-formatted reports
```

## Workflows

**Option 1: Intigriti Program URL**
```
- [ ] Validate INTIGRITI_TOKEN (mandatory)
- [ ] Extract program ID from URL
- [ ] Fetch program data via API (reference/API_REFERENCE.md)
- [ ] Parse domain-based scope with tier assignments
- [ ] Collect program rules and vulnerability types
- [ ] Deploy agents (Tier 1 assets first)
- [ ] Validate PoCs
- [ ] Generate submissions with vuln type taxonomy
```

**Option 2: Program ID**
```
- [ ] Validate INTIGRITI_TOKEN (mandatory)
- [ ] Fetch program via API: GET /external/researcher/v1/programs/{id}
- [ ] Retrieve domain scope from response (embedded in program details)
- [ ] Parse tiers and instructions
- [ ] Deploy agents and generate reports
```

## Scope Format

Intigriti uses domain-based scope (not CSV like HackerOne):
- **Domain**: Target domain or wildcard
- **Type**: Web Application, API, Mobile, Network
- **Tier**: 1-5 (Tier 1 = highest bounty)
- **Instructions**: Per-domain testing guidelines

Use `tools/scope_parser.py` to parse API response.

## Agent Deployment

**Pentester Agent** per domain (tier-prioritized):
- Tier 1 assets: Deploy first, allocate most resources
- Tier 2-3 assets: Deploy in parallel, standard resources
- Tier 4-5 assets: Deploy last, lower priority

**Parallel Execution**:
- 8 domains = 8 Pentester Orchestrators
- Each spawns specialized agents
- Tier 1 findings reviewed first

## PoC Validation (CRITICAL)

**Every finding MUST have**:
1. `poc.py` - Executable exploit script
2. `poc_output.txt` - Timestamped execution proof
3. `workflow.md` - Manual steps (if applicable)
4. Evidence screenshots/videos

## Report Format

Required fields (Intigriti standard):
1. **Title** (vulnerability description, no URL)
2. **Severity** (CVSS v3.1 or v4.0 vector + score)
3. **Domain** (affected in-scope domain)
4. **Vulnerability Type** (from Intigriti taxonomy dropdown)
5. **Description** (Markdown, detailed explanation)
6. **Steps to Reproduce** (numbered, clear)
7. **Impact** (realistic attack scenario)

Use `tools/report_validator.py` to validate.

## Output Structure

```
outputs/intigriti-<program>/
├── findings/
│   ├── finding-001/
│   │   ├── report.md           # Intigriti report
│   │   ├── poc.py              # Validated PoC
│   │   ├── poc_output.txt      # Proof
│   │   └── workflow.md         # Manual steps
├── reports/
│   ├── submissions/
│   │   ├── INTI_CRITICAL_001.md  # Ready to submit
│   │   └── INTI_HIGH_001.md
│   └── SUBMISSION_GUIDE.md
└── evidence/
    ├── screenshots/
    └── http-logs/
```

## Platform Differences (vs HackerOne)

| Aspect | Intigriti | HackerOne |
|--------|-----------|-----------|
| Scope format | Domain-based (API) | CSV file |
| Triage | Managed by Intigriti team | Company-triaged |
| Currency | EUR | USD |
| Vuln classification | Taxonomy dropdown | Free-text |
| Bounty tiers | 1-5 (Tier 1 highest) | Per-severity |
| Report title | No URL in title | URL in title |

See `reference/PLATFORM_GUIDE.md` for full comparison.

## Critical Rules

**MUST DO**:
- **ALWAYS use Intigriti API for scope/program data** (never manual/hardcoded scope)
- **Validate INTIGRITI_TOKEN before any operation** (request from user if missing)
- Validate ALL PoCs before reporting
- Sanitize sensitive data
- Test only in-scope domains
- Follow program-specific rules
- Include CVSS vector string
- Select correct vulnerability type from taxonomy

**NEVER**:
- **Proceed without a validated INTIGRITI_TOKEN**
- **Use hardcoded/manual scope instead of API**
- Report without validated PoC
- Test out-of-scope domains or cause service disruption
- Include real user data

## Quality Checklist

- [ ] Working PoC with poc_output.txt + visual evidence
- [ ] Accurate CVSS score with vector string
- [ ] Correct vulnerability type from taxonomy
- [ ] Step-by-step reproduction + impact + remediation
- [ ] Sensitive data sanitized

## Tools

- `tools/scope_parser.py` - Parse Intigriti domain scope
- `tools/report_validator.py` - Validate report completeness
- `/pentest` skill - Core testing functionality
- Pentester agent - Orchestrates testing

## Usage

```
/intigriti <program_url_or_id>
```
