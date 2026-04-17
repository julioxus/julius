---
name: bugcrowd
description: Bugcrowd bug bounty automation - Manual scope input and program management since Bugcrowd restricts API access. Deploys parallel pentesting agents, validates PoCs, and generates platform-ready submission reports. Use when testing Bugcrowd programs.
---

# Bugcrowd Bug Bounty Hunting

⚠️ **IMPORTANT**: Bugcrowd restricts API access to enterprise customers and high-reputation researchers. This skill uses manual input and fallback methods.

Workflow: Manual scope input → mobile app acquisition → recon → testing via /pentest → PoC validation → submission reports.

## ⚠️ Bugcrowd API Limitations

### **Why No API Access?**
- **Enterprise Only**: Bugcrowd API is restricted to paying enterprise customers
- **High-Rep Researchers**: Invitation-only access for established researchers  
- **No Public API**: Unlike HackerOne, Bugcrowd doesn't offer public researcher APIs

### **Available Methods**:
1. **Manual Input** (Primary method)
2. **Browser Automation** (Future enhancement)
3. **Hybrid Approach** (Copy-paste from program pages)

## Database Integration (MANDATORY)

All engagement data is persisted via the **Bounty Intel MCP tools** (`bounty_*`). These tools are auto-loaded when Claude starts in this project — no imports or env setup needed.

### At engagement start:
- `bounty_upsert_program(platform="bugcrowd", handle=..., company_name=..., scope=..., tech_stack=[...])`
- `bounty_create_engagement(program_id=..., notes="Manual scope assessment")`
- `bounty_update_engagement(engagement_id=..., recon_data=..., attack_surface=...)`
- `bounty_log_activity(action="engagement_started", engagement_id=..., details={...})`

### After each finding:
- `bounty_save_finding(program_id=..., engagement_id=..., title=..., vuln_class=..., severity=..., cvss_vector=..., description=..., steps_to_reproduce=..., impact=..., poc_code=..., poc_output=...)`
- `bounty_record_hunt(target=..., vuln_class=..., success=True, technique=..., tech_stack=[...], platform="bugcrowd")`
- `bounty_upload_evidence(finding_id=..., filename=..., local_path=...)` for screenshots/videos
- `bounty_log_activity(action="finding_created", engagement_id=..., details={...})`

### For building blocks:
- `bounty_save_finding(..., is_building_block=True, building_block_notes="Chain with SSRF or OAuth token theft")`

### For submission reports:
- `bounty_create_report(program_id=..., platform="bugcrowd", title=..., markdown_body=..., finding_id=..., severity=..., report_slug="BC_HIGH_001")`
- `bounty_log_activity(action="report_created", engagement_id=..., details={...})`

### Context queries:
- `bounty_get_findings(program_id=...)` — check what's already been found
- `bounty_search_findings(query="SSRF")` — search across all findings
- `bounty_get_program(program_id=...)` — get scope and OOS rules
- `bounty_get_recon(program_id=...)` — get recon data
- `bounty_suggest_attacks(tech_stack=[...])` — get attack suggestions from hunt memory

### View reports before submission (dashboard):
Reports are reviewed at https://bounty-dashboard-887002731862.europe-west1.run.app/reports — the user approves submission from the dashboard. NEVER submit directly to Bugcrowd without user approval via the dashboard.

## Quick Start (Manual Mode)

```
1. Visit Bugcrowd program page manually
2. Copy program details (scope, rules, bounty table)
3. Use /bugcrowd manual-mode for guided setup
4. Register engagement in DB: db.upsert_program() + db.create_engagement()
5. For mobile assets: use /mobile-app-acquisition to detect emulators and download apps
6. Run /bounty-recon for prioritization + recon pipeline (recon only, no agent deployment)
7. Use /pentest for parallel testing across all in-scope assets
8. For each finding, call /bounty-validation to verify chains and rule out false positives
9. Generate submission reports via the dashboard
```

## Program Discovery & Setup

### **Method 1: Manual Program Setup** (Primary)
```bash
/bugcrowd manual-mode
```
**User provides:**
- Program name and Bugcrowd handle
- In-scope targets (domains, APIs, mobile apps)
- Out-of-scope rules
- Bounty amounts by severity
- Program brief/description

### **Method 2: Direct Program Entry**
```python
# Direct database entry with manual data
program_id = bounty_upsert_program(
    platform="bugcrowd",
    handle="acme-corp",
    company_name="ACME Corporation",
    tech_stack=["web", "api", "mobile"],
    notes="P1: $5000, P2: $2500, P3: $1000, P4: $500, P5: $100"
)
```

## Scope Input Templates

### **Web Application Scope**
```python
scope_web = [
    {
        "asset_type": "url",
        "endpoint": "*.acme.com",
        "tier": "p1",  # Bugcrowd priority level
        "eligible_for_bounty": True,
        "description": "Main application domain"
    },
    {
        "asset_type": "url", 
        "endpoint": "api.acme.com",
        "tier": "p2",
        "eligible_for_bounty": True,
        "description": "Public API endpoints"
    }
]
```

### **Mobile Application Scope**
```python
scope_mobile = [
    {
        "asset_type": "mobile",
        "endpoint": "com.acme.app",
        "tier": "p1",
        "eligible_for_bounty": True,
        "description": "Android app - Google Play Store"
    },
    {
        "asset_type": "mobile",
        "endpoint": "ACME App",
        "tier": "p1", 
        "eligible_for_bounty": True,
        "description": "iOS app - App Store"
    }
]
```

## Scope Extraction Methods

### Method 1: Manual Copy-Paste (Primary Method)
**From Bugcrowd program page, copy:**
1. **Scope section** → Parse into asset list
2. **Out-of-scope rules** → Add to program notes
3. **Bounty table** → Extract by priority level (P1-P5)
4. **Program brief** → Tech stack identification

### Method 2: Guided Interactive Setup
```bash
/bugcrowd interactive
```
**Step-by-step program setup:**
1. Program identification (name, handle, URL)
2. Scope entry (asset by asset)
3. Rules validation
4. Bounty configuration
5. Tech stack detection

## Critical Rules

### Bugcrowd-Specific Guidelines:
1. **Priority Levels**: Bugcrowd uses priority levels (P1-P5) instead of just severity
2. **Submission Format**: Follow Bugcrowd's submission template  
3. **Proof of Concept**: Must include full reproduction steps
4. **Impact Assessment**: Required for all submissions
5. **Duplicate Management**: Check against Bugcrowd's disclosed reports

### Never submit without:
1. Complete proof-of-concept that demonstrates actual impact
2. Verification via /bounty-validation pipeline (5-gate validation)
3. User approval via dashboard review
4. Evidence package (screenshots, request/response, code snippets)
5. Clear reproduction steps for triagers

### Platform-Specific Headers:
```bash
# Always include in requests
User-Agent: BountyIntel/1.0 (Security Research)
X-Bugcrowd-Research: true
```

## Manual Program Setup Process

### **Step 1: Program Page Analysis**
Visit: `https://bugcrowd.com/[program-handle]`

**Extract key information:**
- Program name and company
- Scope table (in-scope assets)
- Out-of-scope rules
- Bounty table (P1-P5 priority levels)
- Program brief and target description
- Technology stack hints

### **Step 2: Scope Normalization**
Convert Bugcrowd scope format to our database format:

```python
# Example conversion
bugcrowd_scope = "*.example.com (P1), api.example.com (P2)"
normalized_scope = [
    {"asset_type": "url", "endpoint": "*.example.com", "tier": "p1", "eligible_for_bounty": True},
    {"asset_type": "url", "endpoint": "api.example.com", "tier": "p2", "eligible_for_bounty": True}
]
```

### **Step 3: Bounty Table Processing**
```python
# Extract bounty amounts from program page
bounty_notes = "P1: $5000, P2: $2500, P3: $1000, P4: $500, P5: $100"
```

## Integration Examples

### **Complete Manual Engagement Flow**
```python
# 1. Manual program creation (user provides data)
program_id = bounty_upsert_program(
    platform="bugcrowd",
    handle="acme-corp",
    company_name="ACME Corporation",
    tech_stack=["web", "api", "mobile", "react", "nodejs"],
    notes="P1: $5000 (Critical), P2: $2500 (High), P3: $1000 (Medium), P4: $500 (Low), P5: $100 (Info)"
)

# 2. Add scope manually
# User provides scope list from program page
scope_data = [
    {"asset_type": "url", "endpoint": "*.acme.com", "tier": "p1", "eligible_for_bounty": True},
    {"asset_type": "url", "endpoint": "api.acme.com", "tier": "p2", "eligible_for_bounty": True},
    {"asset_type": "mobile", "endpoint": "com.acme.app", "tier": "p1", "eligible_for_bounty": True}
]

# 3. Create engagement
engagement_id = bounty_create_engagement(
    program_id=program_id,
    notes="Manual scope setup - P1/P2/P3 assets identified"
)

# 4. Run recon
bounty_recon_results = bounty_recon(
    program_id=program_id,
    engagement_id=engagement_id
)

# 5. Deploy testing agents
pentest_results = pentest(
    program_id=program_id,
    engagement_id=engagement_id
)
```

## Attack Surface Mapping

```python
# Use bounty_get_program() to extract tech stack
program = bounty_get_program(program_id)
tech_stack = program.get("tech_stack", [])

# Get targeted attack suggestions
attacks = bounty_suggest_attacks(tech_stack=tech_stack)
```

## Mobile App Testing

For iOS/Android apps in scope:
```python
# Auto-detect running emulators and download apps
mobile_results = mobile_app_acquisition(
    program_code=target_program["handle"],
    platform="bugcrowd"
)
```

## Evidence Management

All evidence automatically uploads to GCS:
```python
# Screenshots, videos, logs auto-uploaded
evidence_url = bounty_upload_evidence(
    finding_id=finding_id,
    filename="poc_screenshot.png",
    local_path="/tmp/screenshot.png"
)
```

## Validation Pipeline

MANDATORY validation before any submission:
```python
# 5-gate validation system
validation_result = bounty_validation(
    finding_id=finding_id,
    program_id=program_id
)

# Only submit if validation passes all gates
if validation_result["status"] == "passed":
    # Generate submission report
    report_id = bounty_create_report(...)
```

## Platform Integration

### ⚠️ No API Authentication Required
Bugcrowd restricts API access to enterprise customers. This skill operates in **manual mode only**.

**Optional (Enterprise Users):**
```bash
# Only if you have enterprise/high-rep API access
BUGCROWD_EMAIL=your@email.com
BUGCROWD_TOKEN=your_api_token
```

### Submission Preparation
1. Generate markdown report via dashboard
2. Include full evidence chain
3. User reviews and approves
4. **Manual submission to Bugcrowd platform** (copy-paste from dashboard)

## Common Workflows

### **New Program Assessment (Manual Mode)**
```bash
# Step 1: Initialize manual program setup
/bugcrowd manual-mode

# Step 2: User provides program data
# - Program handle (e.g., "acme-corp")  
# - Company name
# - Scope list from Bugcrowd program page
# - Bounty table (P1-P5 amounts)
# - Out-of-scope rules

# Step 3: Automatic registration and recon
# - DB program creation
# - Engagement initialization 
# - Recon pipeline deployment
# - Attack surface mapping
```

### **Interactive Program Setup**
```bash
/bugcrowd interactive acme-corp
```
**Guided walkthrough:**
1. Program identification and validation
2. Asset-by-asset scope entry
3. Priority level assignment (P1-P5)
4. Technology stack detection
5. Bounty configuration
6. Engagement kickoff

### **Quick Manual Scope Entry**
```python
# For experienced users - direct database entry
program_id = bounty_upsert_program(
    platform="bugcrowd",
    handle="acme-corp",
    company_name="ACME Corporation", 
    tech_stack=["web", "api", "mobile"],
    notes="P1: $5000, P2: $2500, P3: $1000 | Manual entry"
)
```

## Common Bugcrowd Program Patterns

### **Web Application Programs**
```python
typical_scope = [
    {"asset_type": "url", "endpoint": "*.company.com", "tier": "p1"},
    {"asset_type": "url", "endpoint": "app.company.com", "tier": "p1"}, 
    {"asset_type": "url", "endpoint": "api.company.com", "tier": "p2"},
    {"asset_type": "url", "endpoint": "admin.company.com", "tier": "p2"}
]
```

### **SaaS Platform Programs**
```python
saas_scope = [
    {"asset_type": "url", "endpoint": "*.platform.io", "tier": "p1"},
    {"asset_type": "api", "endpoint": "api.platform.io/v1/*", "tier": "p1"},
    {"asset_type": "mobile", "endpoint": "com.platform.app", "tier": "p2"}
]
```

## Report Writing Style (MANDATORY — Anti-AI Detection)

**Bugcrowd triagers actively reject reports that look AI-generated.** All reports must be direct, concise, and written in first person. See `/bounty-validation` Report Writing Quality Gate for complete rules.

### Key Rules
- Write in first person for Summary/Impact: "I found", "I tested", "I noticed"
- Steps to Reproduce: instructional style ("Send this request", "Open the page") — no first person
- Keep body under 500 words (excluding code blocks and HTTP dumps)
- NO filler: "This report details...", "It's important to note...", "leveraging...", "poses a significant risk..."
- NO unnecessary sections — omit Remediation, Background, Description unless Bugcrowd requires them
- Every sentence must add information. If removing it loses nothing, delete it.
- **Every command in the report must have been executed and verified working** — never write commands from memory
- Use `tools/report_validator.py` (from HackerOne tools — same checks apply) before submission

### Screenshot Requirements (CRITICAL)
- **Every report MUST include real screenshots** from Burp Suite or browser, captured by the researcher
- Playwright screenshots = supplementary only, never primary
- Before generating any report, ask the user: "Do you have Burp/browser screenshots for this finding?"
- If no screenshots available: **BLOCK report generation**

### Bugcrowd Report Format
```
# [VulnType] — [What] in [Where]

## Summary
[1-2 sentences. What is broken. Why it matters.]

**Priority**: P[1-5]
**VRT**: [Bugcrowd Vulnerability Rating Taxonomy category]
**Asset**: [affected in-scope target]

## Steps to Reproduce
1. [Action with real URL]
   ![step1_description](evidence/step1_screenshot.png)
2. [Next action]
   ![step2_description](evidence/step2_result.png)

## Impact
[2-3 sentences. Concrete attacker gain.]

CVSS:3.1/AV:.../AC:.../... → [score] ([severity])
CWE-[number]
```

## Finding Documentation Standards

Every finding MUST include:
- **Bugcrowd Priority Level** (P1-P5) mapped from CVSS
- **Vulnerability class** from Bugcrowd VRT taxonomy
- **Business impact assessment** (required by Bugcrowd)
- **Full reproduction steps** with **inline real screenshots**
- **Evidence package** (Burp Suite captures, browser screenshots, HTTP request/response)
- **Affected asset** (which scoped target)

## Manual Data Input Templates

### **Program Data Template**
```yaml
program_handle: "acme-corp"
company_name: "ACME Corporation"
bounty_table:
  p1: 5000  # Critical
  p2: 2500  # High  
  p3: 1000  # Medium
  p4: 500   # Low
  p5: 100   # Info
scope:
  - asset_type: "url"
    endpoint: "*.acme.com"
    tier: "p1"
  - asset_type: "mobile"
    endpoint: "com.acme.app"
    tier: "p1"
out_of_scope:
  - "staging.acme.com"
  - "Internal networks"
  - "Third-party domains"
tech_stack: ["react", "nodejs", "postgresql", "aws"]
```

## Error Handling & Fallbacks

- **No API access** → Manual mode (expected)
- **Invalid program handles** → Template creation for user input
- **Missing scope data** → Step-by-step guided entry
- **Validation failures** → Detailed reports with remediation steps
- **Platform changes** → Graceful degradation to manual workflows

## Success Metrics

Track via dashboard:
- **Findings per engagement** (manual programs)
- **Validation success rate** (5-gate system)
- **Submission acceptance rate** (Bugcrowd-specific)
- **Average bounty per priority level** (P1-P5 tracking)
- **Manual setup efficiency** (time to engagement start)