# Intigriti Report Template

## Writing Style (MANDATORY — Anti-AI Detection)

**Reports that read as AI-generated get closed.** See `/bounty-validation` Report Writing Quality Gate for complete rules. Key points:
- First person ("I found", "I tested") — never passive voice
- Under 500 words body (excluding code blocks)
- No filler, no definitions, no marketing language
- No banned AI phrases (see validation gate)
- Every word earns its place

## Submission Template

```markdown
# [VulnType] — [What] in [Where]

**Severity**: [Critical/High/Medium/Low] (CVSS [score])
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
**Domain**: [in-scope domain]
**Vulnerability Type**: [From Intigriti taxonomy]
**CWE**: CWE-[number]

## Summary

[1-2 sentences. What is broken. Why it matters.]

## Steps to Reproduce

1. [Action with real URL and real payload]
   ![step1_description](evidence/step1_screenshot.png)
2. [Next action — real HTTP request or browser action]
   ![step2_description](evidence/step2_result.png)
3. [Observe result]
   ![step3_description](evidence/step3_impact.png)

## Impact

[2-3 sentences. What an attacker gains concretely. No speculation.]
```

**Sections NOT included by default** (add only if program requires):
- Description — redundant with Summary + Steps
- Remediation — optional, only if you have a specific fix
- Affected Users — only if scope matters for severity

## Required Fields

| Field | Required | Notes |
|-------|----------|-------|
| Title | Yes | Under 80 chars, no URLs, format: `[VulnType] — [What] in [Where]` |
| Severity | Yes | CVSS vector + computed score (never guessed) |
| Domain | Yes | Must be in-scope |
| Vulnerability Type | Yes | From Intigriti taxonomy |
| CWE | Yes | e.g., CWE-918 |
| Summary | Yes | 1-2 sentences MAX |
| Steps to Reproduce | Yes | Numbered, with inline real screenshots |
| Impact | Yes | Concrete, no speculation |

## Screenshot Requirements (CRITICAL)

**Primary evidence = real screenshots from the researcher:**
- **Burp Suite**: Repeater tab, HTTP history, Intruder results, Collaborator
- **Browser**: DevTools Network tab, Console, rendered page showing impact

**Rules:**
- Playwright screenshots are supplementary only, never primary
- Claude asks for screenshots before generating reports — if none provided, report is BLOCKED
- No fabricated, reconstructed, or placeholder images
- Name format: `step{N}_{description}.png`

## Evidence — Inline Format (MANDATORY)

Screenshots go **inline within Steps to Reproduce**, immediately after the step they prove. NEVER in a table at the end.

```markdown
1. I sent this request through Burp Repeater:
   ` ` `bash
   curl -v "https://real-target.com/api/endpoint" -d '{"param":"payload"}'
   ` ` `
   ![Burp showing vulnerable response](evidence/step1_burp_response.png)
```

**Required evidence types:**
- **Screenshot** — Always. From Burp Suite or browser (primary), Playwright (supplementary)
- **HTTP request/response** — Always. Real `curl -v` output or Burp export
- **Video** — Complex multi-step only
- **PoC script** — RCE, SQLi, SSRF, auth bypass

## PoC Requirements

- Self-contained (no external deps beyond stdlib)
- Target as argument (not hardcoded)
- Clear output indicating success/failure
- Timestamp in output
- Preferred formats: curl command > Python script > raw HTTP > HTML file
- **Every command must have been executed and verified working before inclusion** — never write commands from memory
