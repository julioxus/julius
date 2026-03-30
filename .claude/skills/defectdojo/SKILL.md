---
name: defectdojo
description: DefectDojo security assessment orchestrator - analyzes engagement scope (SAST + DAST), invokes /pentest as testing engine, converts findings to DefectDojo format, and uploads via API. Also imports existing findings from pentests, bug bounty, scanners, and source code scanning.
---

# DefectDojo Security Assessment & Vulnerability Reporting

Orchestrates security assessments driven by DefectDojo engagements: API auth → scope analysis → testing via /pentest → finding conversion → local validation → upload. Also imports existing findings from other sources.

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
3. Analyze engagement scope from DefectDojo API (determine SAST, DAST, or both)
4. Invoke /pentest in sub-orchestrator mode for active testing
5. Convert /pentest findings to DefectDojo report.md format (YAML frontmatter)
6. Run reproducibility review on all local reports
7. Present summary table → user validates locally
8. AskUserQuestion: approve upload to DefectDojo
9. Import approved findings via API with evidence uploads
10. Verify import and present summary
```

## Phase 1: Local Report Generation (MANDATORY BEFORE ANY API UPLOAD)

**All findings MUST be written to local disk first.** The user reviews and validates reports locally before any DefectDojo interaction. This mirrors the bug bounty workflow (`/hackerone`, `/intigriti`).

### Report File Format

Each finding is a standalone `report.md` with YAML frontmatter + full markdown body:

**For web application / dynamic findings:**
```markdown
---
title: "Short descriptive title"
cwe: 918
cvssv3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N"
cvssv3_score: 7.5
severity: High
static_finding: false
dynamic_finding: true
endpoint: "https://example.com/api/vulnerable-endpoint"
---
```

**For source code review / SAST findings:**
```markdown
---
title: "Short descriptive title"
cwe: 918
cvssv3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N"
cvssv3_score: 7.5
severity: High
static_finding: true
dynamic_finding: false
file_path: "src/app/Domain/Example/Action.php"
line: 42
sast_source_file_path: "src/app/Http/Controllers/ExampleController.php"
sast_source_line: 15
sast_source_object: "$request->input('url')"
sast_sink_object: "Http::get()"
---
```

**Common body structure — writeup style with inline evidence** (same for both types):

Reports MUST follow **writeup format**: screenshots and evidence embedded inline within Steps to Reproduce, immediately after the step they demonstrate. NEVER put evidence in a table at the end. The report should read like a narrative walkthrough where each step shows the command, then the screenshot proving the result.

```markdown
## Description

Technical explanation of the vulnerability. MUST include affected
components, file paths, API routes, or infrastructure elements.

Include relevant code snippets:

` ` `php
// Vulnerable code with file:line reference
$url = $request->input('url');
Http::get($url); // No validation
` ` `

## Impact

Real business impact (verified, not theoretical). What can an attacker
actually achieve? What's the blast radius?

## Steps to Reproduce

### Step 1: Setup and prerequisites

Describe the environment setup and any prerequisites.

![Environment setup](evidence/01_environment.png)

### Step 2: Trigger the vulnerability

` ` `bash
curl -X POST https://example.com/api/vulnerable-endpoint \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
` ` `

**Expected**: HTTP 403 Forbidden
**Actual**: HTTP 200 OK — server fetched the internal metadata

![SSRF response showing internal metadata](evidence/02_ssrf_response.png)

### Step 3: Demonstrate impact

Show the real-world consequence of the vulnerability.

![Impact demonstration](evidence/03_impact.png)

## Mitigation

Actionable remediation guidance with code examples where possible.

` ` `php
// Recommended fix
$allowedHosts = ['cdn.example.com', 'images.example.com'];
$parsed = parse_url($url);
if (!in_array($parsed['host'], $allowedHosts)) {
    abort(400, 'URL host not allowed');
}
` ` `
```

**CRITICAL — Inline evidence rule**: Every report.md MUST embed screenshots using `![caption](evidence/filename.png)` directly after the step they prove. NEVER use a standalone "## Evidence" table at the end. The report reads as a self-contained writeup where each claim is immediately backed by visual proof.

### Frontmatter Fields

**Common (all finding types):**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `title` | string | YES | Short description, no CWE prefix |
| `cwe` | integer | YES | CWE ID (see reference/CWE_MAPPING.md) |
| `cvssv3` | string | YES | Full `CVSS:3.1/AV:.../...` vector |
| `cvssv3_score` | float | YES | **MUST be computed with calculator, never guessed** |
| `severity` | string | YES | Must match CVSS score: Critical(9.0-10.0)/High(7.0-8.9)/Medium(4.0-6.9)/Low(0.1-3.9)/Info(0.0) |
| `static_finding` | bool | YES | `true` for code review/SAST, `false` for dynamic testing |
| `dynamic_finding` | bool | YES | `true` for dynamic/web testing, `false` for SAST |

**For dynamic/web findings** (`dynamic_finding: true`):

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `endpoint` | string | YES | **Must be a valid URL** with `http://` or `https://` protocol. Maps to DD `endpoints` (protocol+host+path). Example: `https://api.example.com/login` |

**For code review / SAST findings** (`static_finding: true`):

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `file_path` | string | YES | Path to the vulnerable file. Maps to DD `file_path` |
| `line` | integer | NO | Line number of the vulnerability. Maps to DD `line` |
| `sast_source_file_path` | string | NO | Source file (where tainted input enters). Maps to DD `sast_source_file_path` |
| `sast_source_line` | integer | NO | Source line number. Maps to DD `sast_source_line` |
| `sast_source_object` | string | NO | Source object/function (e.g., `$request->input('url')`). Maps to DD `sast_source_object` |
| `sast_sink_object` | string | NO | Sink object/function (e.g., `Http::get()`). Maps to DD `sast_sink_object` |

**IMPORTANT**: `endpoint` in DefectDojo ONLY accepts valid URLs. For source code findings, use `file_path` + `line` instead. Never put a file path in `endpoint`.

### Writing Reports

```
For EACH finding:
1. Create directory: outputs/defectdojo-{engagement}/findings/finding-{NNN}/
2. Write report.md with frontmatter + full body (Description, Impact, Steps to Reproduce, Mitigation)
3. Copy/write any evidence files (screenshots, PoC scripts, HTTP logs) into the same directory
4. CVSS score MUST be computed programmatically — use Python or bash calculator, NEVER guess
```

### Developer Reproducibility Review (MANDATORY before upload)

After all reports are written locally, run a **self-review pass** before presenting to the user. For EACH report, verify:

```
1. STEPS TO REPRODUCE — Reproducibility check:
   - [ ] All URLs are FULL (https://...), never relative paths
   - [ ] Auth method explained (how to get tokens/cookies)
   - [ ] Every command is copy-pasteable and will work as written
   - [ ] Request body matches the format that was actually tested (not the SAST assumption)
   - [ ] Expected responses documented (status codes, body snippets)
   - [ ] If a prerequisite exists (Redis injection, secret, 2nd account), it is listed as a numbered step
   - [ ] Category/enum values match what the server actually accepts (test them, don't guess from code)

2. CONSISTENCY — No contradictions:
   - [ ] Endpoint in frontmatter matches the URL in Steps to Reproduce
   - [ ] CVSS vector, score, and severity all align (compute with calculator)
   - [ ] If dynamic_finding: true → frontmatter has `endpoint` field with valid URL
   - [ ] If static_finding: true → frontmatter has `file_path` field
   - [ ] Code snippets reference the ACTUAL vulnerable function/file, not a stale path
   - [ ] Impact claims are supported by evidence (no "could steal admin tokens" without proof of rendering context)

3. HONESTY — No inflation:
   - [ ] Impact describes CONFIRMED impact, not theoretical best-case
   - [ ] If exploitation requires privileged access (kubectl, secrets), state it clearly in Attack Complexity
   - [ ] If a mitigation (like F005 HMAC) raises the bar, document it as prerequisite
   - [ ] CVSS Scope (S:C vs S:U) justified — S:C only if confirmed cross-boundary impact

4. EVIDENCE — Complete chain (see `/bounty-validation` Visual Evidence Standard):
   - [ ] Each finding has evidence/ directory with real captured output
   - [ ] **Browser-renderable vulns** (XSS, CSRF, open redirect, clickjacking): Playwright screenshot showing exploit firing is MANDATORY. Terminal-only = rejected.
   - [ ] **Server-side vulns** (SSRF, race conditions, blind injection): real `curl -v` output or Collaborator interaction proof is MANDATORY. Simulated output = rejected.
   - [ ] HTTP request + response pairs saved as text files
   - [ ] PoC scripts are functional and referenced in Steps to Reproduce
   - [ ] **Never**: simulated terminals, reconstructed responses, placeholder screenshots, AI-generated mock output
```

**If any check fails, fix the report BEFORE presenting to the user.** Do not present reports with known reproducibility issues.

### Validation Before Upload

After the reproducibility review passes:
```
1. Present summary table to user:
   | # | Title | Severity | CVSS | CWE | Endpoint |
2. Tell user: "Reports written to outputs/defectdojo-{engagement}/findings/"
3. AskUserQuestion: "Review the local reports. Which findings should I upload to DefectDojo?"
   options: ["Upload all", "Let me review first and tell you which ones", "Skip upload for now"]
4. If "Let me review first" → STOP and wait for user to come back with specific instructions
5. If "Skip upload" → STOP. Reports remain local for future upload.
6. If "Upload all" → proceed to Phase 2
```

## Phase 2: DefectDojo Upload (ONLY after local validation)

**NEVER proceed to Phase 2 without explicit user approval on Phase 1 reports.**

### Upload Workflow

```
- [ ] Validate API credentials (mandatory first step)
- [ ] Identify product and engagement (search existing via API)
- [ ] **If product/engagement need to be created → AskUserQuestion for approval first**
- [ ] Read approved report.md files from outputs/defectdojo-{engagement}/findings/
- [ ] Parse frontmatter → DefectDojo API fields
- [ ] Deduplicate against existing findings in the engagement
- [ ] Create/find test "Manual Review" (type "Manual Code Review") in engagement via /api/v2/tests/
- [ ] Import findings via POST /api/v2/findings/ (linked to Manual Review test)
- [ ] Upload evidence files from each finding directory
- [ ] Write import results to outputs/defectdojo-{engagement}/reports/defectdojo-import.json
- [ ] Verify and present summary with DD finding IDs + URLs
- [ ] **Show post-upload disclaimer** (see below)
```

### Post-Upload Disclaimer (MANDATORY)

After every successful upload, ALWAYS display this disclaimer to the user:

> **⚠️ Findings uploaded with `active=false` and `verified=false`.**
> All vulnerabilities must be manually reviewed by the security team.
> Until both the `active` and `verified` flags are enabled on each finding, **the corresponding JIRA ticket will NOT be created**.
> Review each finding in DefectDojo and enable both flags after manual validation.

### Cross-References Between Findings

When a finding references another finding, and both are being uploaded:
1. **Plan import order** — create referenced findings first
2. After creating Finding A, get its DefectDojo ID
3. Update Finding B's report.md body to include `[Finding A](https://dojo.example.com/finding/{DD_ID})`
4. Then create Finding B

## Workflows

**Option 1: Security Assessment (Active Testing via /pentest)**

This is the primary orchestration workflow. DefectDojo analyzes the engagement scope and invokes `/pentest` as the testing engine.

```
Phase 0 — Scope Analysis:
- [ ] Validate API credentials
- [ ] Fetch engagement: GET /api/v2/engagements/{id}/ → dates, description, type, status
- [ ] Fetch product: GET /api/v2/products/{product_id}/ → name, description, prod_type
- [ ] Determine test_types from engagement metadata:
      - Description contains repo URL, branch, or "code review" → ["sast"]
      - Description contains target URLs, endpoints, or "penetration" → ["dast"]
      - Both present → ["sast", "dast"]
      - Unclear → AskUserQuestion: "What type of testing? [SAST / DAST / Both]"
- [ ] Extract targets from engagement description (URLs, repos, IP ranges)
- [ ] Build scope contract for /pentest

Phase 1 — Testing (invoke /pentest):
- [ ] Invoke /pentest in sub-orchestrator mode with:
      targets: [extracted from engagement metadata]
      engagement_name: "defectdojo-{engagement-slug}"
      output_base: "outputs/defectdojo-{engagement}/"
      context:
        platform: "defectdojo"
        test_types: [determined in Phase 0]
- [ ] /pentest runs Phase 2 (recon, unless skipped), Phase 3 (user approves plan),
      Phase 4 (deploy executors — SAST and/or DAST), Phase 5 (aggregate findings)
- [ ] Findings land in outputs/defectdojo-{engagement}/processed/findings/

Phase 2 — Local Reports (convert to DefectDojo format):
- [ ] Read findings from outputs/defectdojo-{engagement}/processed/findings/
- [ ] Convert each finding to DefectDojo report.md format:
      - Add YAML frontmatter (title, cwe, cvssv3, severity, static/dynamic flags)
      - For DAST findings: add endpoint field (valid URL)
      - For SAST findings: add file_path, line, sast_source_* fields
      - Map CWE using reference/CWE_MAPPING.md
      - CVSS score MUST be computed programmatically
- [ ] Write to outputs/defectdojo-{engagement}/findings/finding-NNN/report.md
- [ ] Copy evidence files from processed/findings/ to findings/finding-NNN/evidence/
- [ ] Run reproducibility review (see Developer Reproducibility Review below)
- [ ] Present summary table → user validates locally
- [ ] AskUserQuestion: approve upload

Phase 3 — Upload (after user approval):
- [ ] Parse validated report.md files
- [ ] Deduplicate against existing DD findings
- [ ] Create "Manual Review" test in engagement
- [ ] Import approved findings with evidence
- [ ] Write defectdojo-import.json with DD IDs
- [ ] Show post-upload disclaimer
```

**Option 2: Import from Existing Pentest Findings**
```
Phase 1 — Local:
- [ ] Validate API credentials
- [ ] Scan outputs/{engagement}/findings/ for existing validated findings
- [ ] **Require pentester-validator PASS** — only include findings with validated/{finding_id}.json
- [ ] Convert to DefectDojo report format if needed (add frontmatter)
- [ ] Present summary → user validates

Phase 2 — Upload (after user approval):
- [ ] Import approved findings via API
- [ ] Upload evidence (screenshots, PoCs, HTTP logs)
- [ ] Write defectdojo-import.json
```

**Option 3: Import from Scanner Output**
```
- [ ] Validate API credentials
- [ ] Identify product and engagement
- [ ] Detect scanner format and show user what will be imported
- [ ] **AskUserQuestion: get explicit approval before importing scan**
- [ ] Use reimport endpoint: POST /api/v2/reimport-scan/
- [ ] Verify imported findings and present summary
```

**Option 4: Sync Bug Bounty Findings**
```
Phase 1 — Local:
- [ ] Validate API credentials
- [ ] Read findings from outputs/hackerone-* or outputs/intigriti-*
- [ ] **Require pentester-validator PASS** — skip any without validated/{finding_id}.json
- [ ] Convert to DefectDojo report format (outputs/defectdojo-{engagement}/findings/)
- [ ] Present summary → user validates

Phase 2 — Upload (after user approval):
- [ ] Create product per program, engagement per campaign
- [ ] Import approved findings with platform-specific metadata as notes
- [ ] Upload submission reports as evidence
```

**Option 5: Import CVE PoC Generator Findings**
```
Phase 1 — Local:
- [ ] Validate API credentials
- [ ] Read from outputs/processed/cve-pocs/CVE-XXXX-XXXXX/
- [ ] Parse poc.py + report.md → convert to DefectDojo report format
- [ ] Write to outputs/defectdojo-{engagement}/findings/
- [ ] Present summary → user validates

Phase 2 — Upload (after user approval):
- [ ] Import with poc.py as evidence
- [ ] Tag findings with CVE ID for deduplication
```

**Option 6: Import Source Code Scanning Findings**
```
Phase 1 — Local:
- [ ] Validate API credentials
- [ ] Read from outputs/{project}/findings/ produced by /source-code-scanning
- [ ] Ensure SAST fields in frontmatter: static_finding=true, file_path, line, sast_source_*
- [ ] Write to outputs/defectdojo-{engagement}/findings/
- [ ] Present summary → user validates

Phase 2 — Upload (after user approval):
- [ ] Import with static_finding=true, dynamic_finding=false
- [ ] Map file_path, line, sast_source_file_path, sast_source_line, sast_source_object, sast_sink_object
- [ ] Upload code snippets and evidence as attachments
```

## Finding Format (MANDATORY)

Every finding MUST be written as a local `report.md` file first (see Phase 1). The report.md frontmatter maps directly to DefectDojo API fields during Phase 2 upload.

**Markdown formatting**: All text fields (`description`, `impact`, `steps_to_reproduce`, `mitigation`) are rendered as **Markdown** in the DefectDojo UI. Always use proper markdown: `### Headers` for sections, `` ```python ``/`` ```bash `` for code blocks, `| col | col |` for tables, `**bold**` for emphasis, `> quotes` for results, and `-` for lists. Never use plain text formatting — it will render poorly.

**No abbreviations — match local reports exactly**: The DefectDojo finding MUST contain the same level of detail as the local `report.md`. Never summarize, shorten, or omit content when importing. Include all code snippets, all PoC commands, all HTTP responses, all tables, and all evidence. Full URLs, full paths, full commands — never use `...` or ellipsis.

### Frontmatter → DefectDojo API Mapping

**Common fields:**

| report.md frontmatter | DefectDojo API field | Format |
|------------------------|---------------------|--------|
| `title` | `title` | Short description (no CWE prefix) |
| `cwe` | `cwe` | Integer ID (see reference/CWE_MAPPING.md) |
| `cvssv3` | `cvssv3` | Full `CVSS:3.1/AV:.../...` string |
| `cvssv3_score` | `cvssv3_score` | Numeric (0.0-10.0), **computed with calculator** |
| `severity` | `severity` | Must match CVSS score range |
| `static_finding` | `static_finding` | `true` for SAST/code review |
| `dynamic_finding` | `dynamic_finding` | `true` for web/dynamic testing |
| Body `## Description` | `description` | Technical explanation |
| Body `## Impact` | `impact` | Verified business impact |
| Body `## Steps to Reproduce` | `steps_to_reproduce` | Numbered steps with commands |
| Body `## Mitigation` | `mitigation` | Actionable remediation |
| `finding-NNN/evidence/*` | file upload | Screenshots, PoCs, HTTP logs |

**Dynamic findings** (`dynamic_finding: true`):

| report.md frontmatter | DefectDojo API field | Format |
|------------------------|---------------------|--------|
| `endpoint` | `endpoints` | **Valid URL only** (`https://host/path`). Create endpoint object via `/api/v2/endpoints/` then link to finding |

**SAST / code review findings** (`static_finding: true`):

| report.md frontmatter | DefectDojo API field | Format |
|------------------------|---------------------|--------|
| `file_path` | `file_path` | Path to vulnerable file (e.g., `src/app/Domain/Action.php`) |
| `line` | `line` | Line number of vulnerable code |
| `sast_source_file_path` | `sast_source_file_path` | Source file where tainted input enters |
| `sast_source_line` | `sast_source_line` | Source line number |
| `sast_source_object` | `sast_source_object` | Source object/function |
| `sast_sink_object` | `sast_sink_object` | Sink object/function |

## Engagement Types

- **Interactive**: Manual pentest (use for Option 1 active testing, /pentest, /hackerone, /intigriti results)
- **CI/CD**: Automated scans (use for nuclei, ZAP, Burp scan imports via Option 3)

## Supported Scanner Imports

DefectDojo reimport accepts 150+ formats. Common ones:
- `Nuclei Scan` | `Nmap XML` | `ZAP Scan` | `Burp REST API`
- `Trivy Scan` | `Prowler` | `Semgrep JSON`
- `Generic Findings Import` (CSV/JSON for custom formats)

Use `tools/scanner_mapper.py` to identify format from file.

## Output Structure

```
outputs/defectdojo-{engagement}/
├── findings/                       # LOCAL REPORTS (Phase 1 — written before any upload)
│   ├── finding-001/
│   │   ├── report.md               # Frontmatter + full markdown (Description, Impact, Steps, Mitigation)
│   │   ├── poc.py                   # PoC script (if applicable)
│   │   ├── poc_output.txt           # PoC execution output
│   │   └── evidence/               # Screenshots, HTTP logs, etc.
│   │       ├── request.txt
│   │       └── screenshot.png
│   ├── finding-002/
│   │   ├── report.md
│   │   └── evidence/
│   └── ...
├── reports/
│   └── defectdojo-import.json      # Phase 2: Import results with DD finding IDs + URLs
├── activity/
│   └── defectdojo-reporter.log     # NDJSON activity log
└── evidence/
    └── uploaded/                    # Tracking of files uploaded to DD
```

**Naming convention**: `defectdojo-{engagement}` uses the engagement name slug (lowercase, hyphens). Examples:
- Engagement "SLIDES - Presentation Maker 3.1" → `outputs/defectdojo-slides-pmaker-3.1/`
- Engagement "SRE Magnific Audit" → `outputs/defectdojo-sre-magnific/`

## Critical Rules

**MUST DO**:
- **ALWAYS write local reports first (Phase 1)** — NEVER call the DefectDojo API to create findings without having local report.md files written and validated by the user
- **Validate DEFECTDOJO_URL + DEFECTDOJO_TOKEN before any operation**
- **ASK USER APPROVAL BEFORE UPLOADING** — present summary table, tell user where reports are on disk, get explicit confirmation before Phase 2
- **CREATE FINDINGS UNDER A TEST** — always create/find a test named "Manual Review" (type "Manual Code Review") in the engagement
- **ALWAYS set `active: false` and `verified: false`** when creating findings via POST /api/v2/findings/. Findings are created as drafts — the security team activates and verifies them after their own review. Never set active=true or verified=true.
- **EMBED SCREENSHOTS inline in `steps_to_reproduce`** — when a finding has PoC screenshot evidence, upload the screenshot file first via the files endpoint, then reference it inline within the Steps to Reproduce section at the exact step where the evidence is relevant (e.g., after the curl command, embed the screenshot showing the response). This makes the PoC self-contained and reviewable without switching to the evidence tab.
- Map CWE IDs accurately (reference/CWE_MAPPING.md)
- Deduplicate against existing findings
- Upload all evidence files from finding directories
- Verify import completeness

**NEVER**:
- **Skip Phase 1 (local reports)** — even if findings come from another tool or previous engagement, they MUST exist as local report.md files before upload
- **Proceed without validated API credentials**
- **Create or modify ANY resource in DefectDojo without explicit user approval first**
- **Import findings without validated PoC** — every finding MUST have a working proof-of-concept with captured evidence
- **Import findings that failed pentester-validator** — check for `validated/{finding_id}.json` before import
- Import fabricated or placeholder findings
- Overwrite existing findings without user approval
- Skip deduplication

## Tools

- `/pentest` skill - Testing engine (invoked in sub-orchestrator mode for Option 1)
- `/bounty-validation` skill - Finding validation gate (optional, for quality assurance)
- `tools/iap_browser_auth.py` - IAP cookie acquisition via Playwright (cache → browser login)
- `tools/finding_importer.py` - Import findings to DefectDojo API
- `tools/scanner_mapper.py` - Map scanner output to DD import format
- `reference/CWE_MAPPING.md` - Vulnerability type → CWE ID mapping
- `reference/API_REFERENCE.md` - DefectDojo API v2 reference

## Usage

```
/defectdojo <product_name> [engagement_name]
```
