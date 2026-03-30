# Intigriti Report Template

## Submission Template

```markdown
# [Vulnerability Type] in [Component/Feature]

**Severity**: [Critical/High/Medium/Low] (CVSS [score])
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
**Domain**: [in-scope domain]
**Vulnerability Type**: [From Intigriti taxonomy]

## Summary

[2-3 sentence description of the vulnerability, its location, and its impact]

## Description

[Detailed technical explanation of the vulnerability]

- Root cause analysis
- Affected endpoints/parameters
- Authentication requirements (if any)

## Steps to Reproduce

1. Navigate to `https://[domain]/[path]`
2. [Action with specific parameters]
3. Enter the following payload: `[payload]`
4. Observe [specific behavior indicating vulnerability]
5. [Additional steps if needed]

## Proof of Concept

### HTTP Request

```http
POST /api/endpoint HTTP/1.1
Host: [domain]
Content-Type: application/json

{"param": "[payload]"}
```

### HTTP Response

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"result": "[evidence of vulnerability]"}
```

### PoC Script

```python
# See attached poc.py for automated exploitation
python3 poc.py --target https://[domain]/[path]
```

### Screenshots/Evidence

[Attach screenshots showing the vulnerability]

## Impact

[Realistic attack scenario - what can an attacker achieve?]

- **Confidentiality**: [Data that can be accessed]
- **Integrity**: [Data that can be modified]
- **Availability**: [Service disruption potential]

**Affected Users**: [Scope of impact - all users, specific roles, etc.]

## Remediation

[Specific, actionable fix recommendations]

1. [Primary fix]
2. [Secondary mitigation]
3. [Additional hardening]
```

## Required Fields Checklist

| Field | Required | Notes |
|-------|----------|-------|
| Title | Yes | No URL, describe the vulnerability |
| Severity | Yes | CVSS score + vector string |
| Domain | Yes | Must be in-scope |
| Vulnerability Type | Yes | From Intigriti taxonomy |
| Summary | Yes | 2-3 sentences |
| Steps to Reproduce | Yes | Numbered, reproducible |
| PoC | Yes | Code, HTTP requests, or screenshots |
| Impact | Yes | Realistic attack scenario |
| Remediation | Recommended | Shows professionalism |

## PoC Format Preferences

### Preferred (in order)

1. **Python script** (`poc.py`) - Most reproducible
2. **curl command** - Quick reproduction
3. **Raw HTTP request** - Universal format
4. **HTML file** - For client-side vulns (XSS, CSRF)
5. **Burp Suite request** - If Burp is available

### PoC Requirements

- Must be **self-contained** (no external dependencies beyond standard libs)
- Must include **target as argument** (not hardcoded)
- Must produce **clear output** indicating success/failure
- Must include **timestamp** in output

## Evidence Requirements — Inline Writeup Format (MANDATORY)

Reports MUST embed evidence **inline within Steps to Reproduce**, immediately after the step they demonstrate. The report reads as a self-contained writeup where each claim is backed by visual proof at the point it's made.

**Format**: Use `![caption](evidence/filename.png)` after each step:

```markdown
### Step 1: Send crafted request

` ` `bash
curl -X POST https://target.com/api/endpoint ...
` ` `

**Expected**: HTTP 403
**Actual**: HTTP 200 — vulnerability triggered

![Server returned internal metadata](evidence/01_ssrf_response.png)

### Step 2: Demonstrate impact
...
![Account takeover confirmed](evidence/02_account_takeover.png)
```

**NEVER** put evidence in a table at the end of the report. Every screenshot must appear next to the step it proves.

**Required evidence types** (embed inline where relevant):

- **Screenshot** — Always. Captured with Playwright for browser vulns, terminal output for server-side.
- **HTTP request/response** — Always. Raw `curl -v` output or Burp export.
- **Video** — Complex multi-step vulnerabilities only.
- **PoC script** — RCE, SQLi, SSRF, auth bypass.
- **Impact demonstration** — Account takeover, data access.
